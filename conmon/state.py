from typing import TYPE_CHECKING, List, Match, Optional, Set, Tuple, Type

from conmon.logging import get_logger

if TYPE_CHECKING:
    from .__main__ import ConanParser

CONMON_LOG = get_logger("CONMON")


class State:
    SKIP_NEXT = False

    def __init__(self, parser: "ConanParser"):
        self.finished = False
        self.stopped = False
        self.screen = parser.screen

    def deactivate(self):
        assert self.finished is False
        self._deactivate(final=False)
        assert self.finished is True

    def _deactivate(self, final=False):
        self.finished = True
        self.stopped = final

    def activated(self, parsed_line: Match) -> bool:
        raise NotImplementedError

    def process(self, parsed_line: Match) -> None:
        raise NotImplementedError


class StateMachine:
    def __init__(
        self,
        parser: "ConanParser",
        *states: Type[State],
        default: Optional[Type[State]] = None,
    ):
        self.screen = parser.screen
        self.parser = parser
        self._active: Set[State] = set()  # currently active
        self._running: List[State] = []  # can be executed
        self._default = default(parser) if default else None

        if self._default:
            self.add(self._default)
        for state in states:
            self.add(state(parser))

    def add(self, state: State):
        assert not state.stopped
        assert state not in self._running
        self._running.append(state)

    @property
    def active_classes(self) -> Tuple[Type[State], ...]:
        return tuple(type(instance) for instance in self._active)

    def active_instance(self) -> Optional[State]:
        for state in self._active:
            return state
        return None

    def running_instances(self) -> Tuple[State, ...]:
        return tuple(self._running)

    def activate(self, state: State):
        state.finished = False
        self._active.add(state)

    def deactivate(self, state: State):
        if not state.finished:
            state.deactivate()
        self._active.remove(state)
        if state.stopped:
            self._running.remove(state)

    def deactivate_all(self):
        for state in tuple(self._active):
            self.deactivate(state)

    def process_hooks(self, parsed_line: Match) -> None:
        skip_next = []
        for state in tuple(self._active):
            if not state.finished:
                state.process(parsed_line)
            if state.finished:
                self.deactivate(state)
                skip_next.append(state.SKIP_NEXT)

        if any(skip_next):
            return

        activated = []
        for state in tuple(self._running):
            if state not in self._active and state.activated(parsed_line):
                activated.append(state)

        if activated:
            if len(activated) > 1:
                CONMON_LOG.warning(
                    "overlapping states: %s",
                    ", ".join(type(state).__name__ for state in activated),
                )
            self.deactivate_all()
            for state in activated:
                self.activate(state)

        if not self._active and self._default and not self._default.stopped:
            self.activate(self._default)
            self._default.process(parsed_line)
