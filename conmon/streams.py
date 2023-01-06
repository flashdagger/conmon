# pylint: disable=no-name-in-module
import sys
from collections import deque
from contextlib import suppress
from functools import partial
from itertools import groupby
from operator import itemgetter

with suppress(ImportError):
    from select import epoll, EPOLLIN  # type: ignore

# from queue import Empty, Queue
from subprocess import Popen
from threading import Condition, Lock, Thread
from time import monotonic
from typing import Deque, Dict, Generic, IO, Iterator, Optional, Tuple, TypeVar, Union

_T = TypeVar("_T")


class Empty(Exception):
    pass


class Queue(Generic[_T]):
    """
    implementation of a multi-producer single-consumer queue
    due to single consumer restriction it is about x60 times faster then queue.Queue
    """

    SENTINEL = object()

    __class_getitem__ = classmethod(list)

    def __init__(self, maxlen: Optional[int] = None):
        self.queue: Deque[_T] = deque(maxlen=maxlen)
        self._cond = Condition(Lock())
        self._empty = True

    def put(self, value: _T):
        self.queue.append(value)

        if not self._empty:
            return

        condition = self._cond
        with condition:
            self._empty = False
            condition.notify()

    def get(self, block=True, timeout: Optional[float] = None, default=SENTINEL) -> _T:
        if block and self._empty:
            with self._cond:
                self._cond.wait(timeout=timeout)

        return self.get_nowait(default=default)

    def get_nowait(self, default=SENTINEL) -> _T:
        try:
            return self.queue.popleft()
        except IndexError as exc:
            if not self._empty:
                with self._cond:
                    self._empty = True
            if default == self.SENTINEL:
                raise Empty() from exc
        return default

    def qsize(self) -> int:
        return len(self.queue)

    def empty(self) -> bool:
        return not self.queue

    def full(self) -> bool:
        queue = self.queue
        maxlen = queue.maxlen
        return bool(maxlen) and len(queue) == maxlen

    def __bool__(self) -> bool:
        return bool(self.queue)

    def __len__(self) -> int:
        return len(self.queue)

    def __repr__(self) -> str:
        return f"<{self.queue!r}>".replace("deque", "Queue")


class ProcessStreamHandler:
    def __init__(self, proc: Popen):
        queue: Queue[Tuple[str, str]] = Queue()
        self.queue = queue
        self.ts_offset = monotonic()
        threads: Dict[str, Thread] = {}
        if sys.platform == "experimental":
            # experimental, works only on linux
            threads["select"] = Thread(
                target=self.pollreader,
                args=(proc, queue),
                name=f"selectreader<pid={proc.pid}>",
            )
        else:
            for pname in ("stderr", "stdout"):
                pipe: Optional[IO] = getattr(proc, pname)
                if pipe:
                    threads[pname] = Thread(
                        target=self.pipereader,
                        kwargs=dict(pipe_id=pname, pipe=pipe, queue=self.queue),
                        name=f"pipereader<pid={proc.pid}, {pname}={pipe.name}>",
                    )

        self._threads = threads
        for thread in threads.values():
            thread.start()

    @staticmethod
    def pollreader(proc: Popen, queue: Queue) -> None:
        pmapping = {}
        poll_obj = epoll()
        for pname in ("stderr", "stdout"):
            pipe = getattr(proc, pname)
            if pipe:
                pmapping[pipe.fileno()] = (pname, pipe)
                poll_obj.register(pipe, EPOLLIN)

        def readable_pipes(timeout=None):
            return [
                pmapping[_fileno]
                for _fileno, _event in poll_obj.poll(timeout)
                if _fileno in pmapping
            ]

        while pmapping:
            for name, pipe in readable_pipes():
                line = pipe.readline()
                if line:
                    queue.put((name, line))
                else:
                    poll_obj.unregister(pipe)
                    del pmapping[pipe.fileno()]

    @staticmethod
    def pipereader(pipe_id: str, pipe: IO[str], queue: Queue) -> None:
        queue_put = queue.put
        with suppress(ValueError):
            for line in iter(pipe.readline, ""):
                queue_put((pipe_id, line))

    @property
    def exhausted(self) -> bool:
        return self.queue.empty() and not any(
            thread.is_alive() for thread in self._threads.values()
        )

    def iterqueue(
        self, block: Union[bool, float] = True, onlyfirst=False
    ) -> Iterator[Tuple[str, str]]:
        """nowait all: block=False, onlyfirst is ignored
        block only first: block=True, onlyfirst is ignored
        timeout only first: block=float, onlyfirst=True
        timeout all: block=float, onlyfirst=False
        """
        if self.exhausted:
            return
        arg_block, arg_timeout = (
            (True, block) if isinstance(block, float) else (block, None)
        )
        queue_get = partial(self.queue.get, arg_block, arg_timeout)
        with suppress(Empty):
            if block is True or onlyfirst and arg_timeout is not None:
                yield queue_get()
                queue_get = partial(self.queue.get_nowait)
            else:
                assert not (arg_block and arg_timeout is None)
            while True:
                yield queue_get()

    def iterpipes(
        self, block: Union[bool, float] = False, onlyfirst=False
    ) -> Iterator[Tuple[str, float, Iterator[str]]]:
        """
        return the name ('stderr' or 'stdout'), timestamp and lines
        from the next available pipe output

        for the arguments see documentation of iterqueue()
        """
        ts_offset = self.ts_offset
        pipe_id: str
        for pipe_id, group in groupby(
            self.iterqueue(block=block, onlyfirst=onlyfirst), key=itemgetter(0)
        ):
            yield pipe_id, monotonic() - ts_offset, map(itemgetter(1), group)

    def assert_stdout(
        self, block: Union[bool, float] = False, onlyfirst=False
    ) -> Tuple[str, ...]:
        for pipe_id, group in groupby(
            self.iterqueue(block=block, onlyfirst=onlyfirst), key=itemgetter(0)
        ):
            lines = map(itemgetter(1), group)
            assert pipe_id == "stdout", f"unexpected {pipe_id}: {''.join(lines)}"
            return tuple(lines)
        return ()

    def flush_queue(self):
        for _ in self.iterqueue(block=False):
            pass

    def join(self):
        for thread in self._threads.values():
            thread.join()
