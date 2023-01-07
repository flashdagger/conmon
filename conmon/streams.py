import contextlib
import sys
from collections import deque
from contextlib import suppress
from functools import partial
from itertools import groupby
from operator import itemgetter
from subprocess import Popen
from threading import Condition, Lock, Thread
from time import monotonic
from typing import (
    AnyStr,
    Deque,
    Dict,
    Generic,
    IO,
    Iterator,
    Optional,
    Tuple,
    TypeVar,
    Union,
    Generator,
)

_T = TypeVar("_T")


class Empty(Exception):
    pass


class Full(Exception):
    pass


class Queue(Generic[_T]):
    """
    reimplementation of queue.Queue: a multi-producer multi-consumer queue
    """

    SENTINEL = object()

    __class_getitem__ = classmethod(list)

    def __init__(self, maxsize: int = 0):
        self.queue: Deque[_T] = deque(maxlen=maxsize or None)
        self._mutex = mutex = Lock()
        self._not_empty = Condition(mutex)
        self._not_full = Condition(mutex)

    @contextlib.contextmanager
    def deque(self, block=True, timeout=None) -> Generator[Deque[_T], None, None]:
        queue = self.queue
        mutex = self._mutex
        if not mutex.acquire(
            blocking=block, timeout=timeout if block and timeout is not None else -1
        ):
            raise RuntimeError("Lock was not acquired")

        try:
            yield queue
        finally:
            if queue:
                self._not_empty.notify()
            elif queue.maxlen and len(queue) < queue.maxlen:
                self._not_full.notify()
            mutex.release()

    def put(self, value: _T, block=True, timeout=None):
        queue = self.queue
        maxlen = queue.maxlen

        def not_full():
            return not maxlen or len(queue) < maxlen

        with self._mutex:
            if not_full() or (
                block and self._not_full.wait_for(not_full, timeout=timeout)
            ):
                queue.append(value)
                self._not_empty.notify()
            else:
                raise Full()

    def get(self, block=True, timeout: Optional[float] = None, default=SENTINEL) -> _T:
        queue = self.queue
        value = default

        with self._mutex:
            if (
                queue
                or block
                and self._not_empty.wait_for(lambda: bool(queue), timeout=timeout)
            ):
                value = queue.popleft()
                self._not_full.notify()

        if value is self.SENTINEL:
            raise Empty()

        return value

    def get_nowait(self, default=SENTINEL) -> _T:
        return self.get(block=False, default=default)

    def qsize(self) -> int:
        with self._mutex:
            return len(self.queue)

    def empty(self) -> bool:
        with self._mutex:
            return not self.queue

    def full(self) -> bool:
        queue = self.queue
        maxlen = queue.maxlen
        with self._mutex:
            return bool(maxlen) and len(queue) == maxlen

    def __bool__(self) -> bool:
        with self._mutex:
            return bool(self.queue)

    def __len__(self) -> int:
        with self._mutex:
            return len(self.queue)

    def __repr__(self) -> str:
        return f"<{self.queue!r}>".replace("deque", "Queue")


class ProcessStreamHandler:
    def __init__(self, proc: Popen):
        queue: Queue[Tuple[str, str]] = Queue()
        self.queue = queue
        self.ts_offset = monotonic()
        threads: Dict[str, Thread] = {}
        if sys.platform is None:
            # experimental, works only on linux
            # uses less system resources but has higher latency
            threads["select"] = Thread(
                target=self.feedqueue,
                args=(queue, polling_iterlines(proc)),
                name=f"selectreader<pid={proc.pid}>",
            )
        else:
            for pname in ("stderr", "stdout"):
                pipe: Optional[IO] = getattr(proc, pname)
                if pipe:
                    threads[pname] = Thread(
                        target=self.feedqueue,
                        args=(queue, iterlines(pipe, pname)),
                        name=f"pipereader<pid={proc.pid}, {pname}={pipe.name}>",
                    )

        self._threads = threads
        for thread in threads.values():
            thread.start()

    @staticmethod
    def feedqueue(queue: Queue, iterator: Iterator) -> None:
        queue_put = queue.put
        for item in iterator:
            queue_put(item)

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
        with self.queue.deque() as queue:
            queue.clear()

    def join(self, timeout: Optional[float] = None):
        for thread in self._threads.values():
            thread.join(timeout=timeout)


def iterlines(pipe: IO[AnyStr], pipename: str) -> Iterator[Tuple[str, AnyStr]]:
    while True:
        line = pipe.readline()
        if not line:
            break
        yield pipename, line


# pylint: disable=import-outside-toplevel, no-name-in-module
def polling_iterlines(
    proc: Popen, pipenames: Tuple[str, ...] = ("stderr", "stdout")
) -> Iterator[Tuple[str, AnyStr]]:
    from select import EPOLLIN, epoll  # type: ignore

    pmapping = {}
    poll_obj = epoll()
    for pname in pipenames:
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
                yield name, line
            else:
                poll_obj.unregister(pipe)
                del pmapping[pipe.fileno()]
