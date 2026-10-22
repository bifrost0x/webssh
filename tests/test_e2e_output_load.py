"""Cadence of the disposable TUI workload must not compound SSH backpressure."""
import importlib.util
from pathlib import Path

import pytest


_spec = importlib.util.spec_from_file_location('e2e_output_load_fixture', Path(__file__).parent / 'e2e' / 'output_load.py')
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Stop:
    def __init__(self, clock, cancel_wait=None):
        self.clock = clock
        self.stopped = False
        self.waits = []
        self.cancel_wait = cancel_wait

    def is_set(self):
        return self.stopped

    def wait(self, delay):
        self.waits.append(delay)
        self.clock.now += delay
        if self.cancel_wait is not None and len(self.waits) >= self.cancel_wait:
            self.stopped = True
        return self.stopped


def test_frames_keep_absolute_twenty_hertz_slots_without_skipping_any_sequence():
    clock = Clock()
    stop = Stop(clock)
    emitted = []

    def emit(sequence):
        emitted.append((sequence, clock()))
        clock.now += 0.01

    completed = _fixture._produce_frames(emit, stop, started=0.0, clock=clock)
    assert completed == 240
    assert [sequence for sequence, _ in emitted] == list(range(1, 241))
    assert [when for _, when in emitted] == pytest.approx([i * 0.05 for i in range(240)])


def test_blocking_emission_does_not_add_fifty_milliseconds_after_each_backpressure_wait():
    clock = Clock()
    stop = Stop(clock)
    emitted = []

    def emit(sequence):
        emitted.append(sequence)
        clock.now += 0.12

    completed = _fixture._produce_frames(emit, stop, started=0.0, clock=clock)
    assert completed == 240
    assert emitted == list(range(1, 241))
    assert clock() == pytest.approx(28.8)
    assert stop.waits == [0.0] * 240


def test_cadence_respects_cancellation_before_the_next_frame():
    clock = Clock()
    stop = Stop(clock, cancel_wait=2)
    emitted = []
    assert _fixture._produce_frames(emitted.append, stop, started=0.0, clock=clock) == 1
    assert emitted == [1]
    emitted.clear()
    assert _fixture._produce_frames(emitted.append, stop, started=0.0, clock=clock) == 0
    assert emitted == []


def test_cancelled_emission_is_not_reported_as_a_completed_frame():
    clock = Clock()
    stop = Stop(clock)
    emitted = []

    def emit(sequence):
        emitted.append(sequence)
        return sequence < 4

    assert _fixture._produce_frames(emit, stop, started=0.0, clock=clock) == 3
    assert emitted == [1, 2, 3, 4]
