
import sys
import time
import signal
from array import array
from threading import Lock

try:
    from fcntl import ioctl
    import termios
except ImportError, e:
    # Do nothing if ioctl, termios modules doesn't exists
    ioctl = lambda *args: None

    class FakeTermios(object):
        TIOCGWINSZ = None
    termios = FakeTermios()


DEFAULT_TERMINAL_WIDTH = 79
MAX_TITLE_WIDTH = 32


class ProgressBarComponent(object):

    def update(self, bar):
        pass


class ProgressBarHorizontalComponent(object):

    def update(self, bar, width):
        pass


class BarComponent(ProgressBarHorizontalComponent):

    def __init__(self, marker='#', left='|', right='|'):
        self.marker = marker
        self.left = left
        self.right = right
        self._left_right_length = len(left) + len(right)

    def update(self, bar, width):
        percent = bar.percent
        component_width = width - self._left_right_length
        markers_width = int(percent * component_width / 100)
        marker_part = self.marker * markers_width
        return self.left + marker_part.ljust(component_width) + self.right


class PercentComponent(ProgressBarComponent):

    def update(self, bar):
        return '%3d%%' % bar.percent


class ETA(ProgressBarComponent):

    def format_time(self, seconds):
        return time.strftime('%H:%M:%S', time.gmtime(seconds))

    def update(self, bar):
        if bar.value == 0:
            return ' ETA: --:--:--'
        if bar.finished:
            return 'Time: %s' % self.format_time(bar.seconds_elapsed)
        eta = bar.seconds_elapsed * bar.max_value / bar.value
        eta -= bar.seconds_elapsed
        return ' ETA: %s' % self.format_time(eta)


class FileTransferSpeedComponent(ProgressBarComponent):

    def __init__(self, format='%3.2f %s', units='BKMGTP'):
        self.format = format
        self.units = [c for c in units]

    def update(self, bar):
        if bar.seconds_elapsed < 2e-6:  # equal zero
            bps = 0.0
        else:
            bps = float(bar.value) / bar.seconds_elapsed
        speed = bps
        for u in self.units:
            if speed < 1000:
                break
            speed /= 1000
        return (self.format % (speed, u + '/s')).rjust(10)


class TransferedBytesComponent(ProgressBarComponent):

    def __init__(self, format='%3.2f %s', units='BKMGTP'):
        self.format = format
        self.units = [c for c in units]

    def human_readable(self, value, format):
        value = float(value)
        for u in self.units:
            if value < 1024:
                break
            value /= 1024
        return format % (value, u)

    def update(self, bar):
        now = self.human_readable(bar.value, self.format)
        max = self.human_readable(bar.max_value, self.format)
        return ('%s/%s' % (now, max)).rjust(17)


DEFAULT_COMPONENTS = (FileTransferSpeedComponent(), ' ', BarComponent(), ' ',
                      PercentComponent(), ' ', TransferedBytesComponent(), ' ',
                      ETA())


class ProgressBar(object):

    def __init__(self, max_value=100, components=DEFAULT_COMPONENTS,
                 terminal_width=None, fd=sys.stderr, title=None,
                 fixed_title_width=True, quite=False):
        self._max_value = max_value
        self._components = components
        self._fd = fd
        self._value = 0
        self._finished = False
        self._set_signal = False
        self._last_percent = None
        self._start_time = None
        self._time_spent = None
        self._draw = not quite
        if title:
            title = title[:MAX_TITLE_WIDTH]
            if len(title) > MAX_TITLE_WIDTH - 3:
                title = title[:-3] + '...'
            if fixed_title_width:
                title = title.ljust(MAX_TITLE_WIDTH)
            self._components = (title, ' ') + components
        if terminal_width is None:
            try:
                self.resize_handler(None, None)
                signal.signal(signal.SIGWINCH, self.resize_handler)
                self._set_signal = True
            except Exception:
                self._terminal_width = DEFAULT_TERMINAL_WIDTH
        else:
            self._terminal_width = terminal_width
        self._lock = Lock()

    def resize_handler(self, signum, frame):
        result = array('h', ioctl(self._fd, termios.TIOCGWINSZ, '\0' * 8))
        self._terminal_width = result[1]

    def _format_components(self):
        result = []
        width = 0
        horizontal_fillers_idx = []
        horizontal_fillers_count = 0
        for idx, component in enumerate(self._components):
            if isinstance(component, ProgressBarHorizontalComponent):
                result.append(component)
                horizontal_fillers_idx.append(idx)
                horizontal_fillers_count += 1
            elif isinstance(component, ProgressBarComponent):
                out_width = component.update(self)
                result.append(out_width)
                width += len(out_width)
            elif isinstance(component, basestring):
                result.append(component)
                width += len(component)
        horizontal_filler_width = int(self._terminal_width - width)
        horizontal_filler_width /= horizontal_fillers_count
        for idx in horizontal_fillers_idx:
            result[idx] = result[idx].update(self, horizontal_filler_width)
        return ''.join(result).ljust(self._terminal_width)

    @property
    def finished(self):
        return self._finished

    @property
    def percent(self):
        """ Returns percent of the progress """
        return self.value * 100.0 / self._max_value

    @property
    def seconds_elapsed(self):
        return self._time_spent

    @property
    def max_value(self):
        return self._max_value

    def _need_update(self):
        return self.percent != self._last_percent

    def _get_value(self):
        return self._value

    def _set_value(self, value):
        if value is None:
            value = self.value + 1
        if self._value < 0:
            self._value = 0
        if self._value > self._max_value:
            value = self._max_value
        self._value = value
        if self._need_update() or not self._finished:
            if not self._start_time:
                self._start_time = time.time()
            self._time_spent = time.time() - self._start_time
            self._last_percent = self.percent
            if self._value >= self._max_value:
                self._finished = True
        tmpl = '%s\n' if self._finished else '%s\r'
        self._lock.acquire()
        if self._draw or (self._max_value and self._finished):
            self._fd.write(tmpl % self._format_components())
        self._lock.release()

    value = property(_get_value, _set_value)

    def callback(self, value):
        self.value += value

    def clear(self):
        self._draw = False

    def start(self):
        """ Start progress """
        self.value = 0

    def finish(self):
        """ Finish progress """
        if not self._finished:
            self._finished = True
            self.value = self._max_value
        if self._set_signal:
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)
