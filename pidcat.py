#!/usr/bin/env -S python -u

'''
Copyright 2009, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

# Script to highlight adb logcat output for console
# Originally written by Jeff Sharkey, http://jsharkey.org/
# Piping detection and popen() added by other Android team members
# Package filtering and output improvements by Jake Wharton, http://jakewharton.com
# Refactor and better printing of tags by Luiz Stangarlin, https://github.com/Luiz-Monad

import argparse
import sys
import re
import subprocess
from time import sleep
from subprocess import PIPE
from colorama import init, AnsiToWin32

__version__ = '3.0.0'

LOG_LEVELS = 'VDIWEF'
LOG_LEVELS_MAP = dict([(LOG_LEVELS[i], i) for i in range(len(LOG_LEVELS))])

TASK_LINE = re.compile(r'.*TaskRecord.*A[= ]([^ ^}]*)')
PID_LINE  = re.compile(r'^\w+\s+(\w+)\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w\s([\w|\.|\/]+)$')
PID_START = re.compile(r'^Start proc ([a-zA-Z0-9._:]+) for ([a-z]+ [^:]+): pid=(\d+) uid=(\d+) gids=(.*)$')
PID_START_5_1 = re.compile(r'^Start proc (\d+):([a-zA-Z0-9._:]+)/[a-z0-9]+ for (.*)$')
PID_START_DALVIK = re.compile(r'^>>>>> ([a-zA-Z0-9._:]+) \[ userId:0 \| appId:(\d+) \]$')
PID_KILL  = re.compile(r'^Killing (\d+):([a-zA-Z0-9._:]+)/[^:]+: (.*)$')
PID_LEAVE = re.compile(r'^No longer want ([a-zA-Z0-9._:]+) \(pid (\d+)\): .*$')
PID_DEATH = re.compile(r'^Process ([a-zA-Z0-9._:]+) \(pid (\d+)\) has died.?$')
LOG_LINE  = re.compile(r'^[\[] \d+-\d+ \d+:\d+:\d+[.]\d+ (.+?):(.+?) ([A-Z])\/(.+?) [\]]$')
BUG_LINE  = re.compile(r'.*nativeGetEnabledTags.*')
BACKTRACE_LINE = re.compile(r'^#(.*?)pc\s(.*?)$')
# StrictMode policy violation; ~duration=319 ms: android.os.StrictMode$StrictModeDiskWriteViolation: policy=31 violation=1
STRICT_MODE_LINE = re.compile(r'^(StrictMode policy violation)(; ~duration=)(\d+ ms)')
# GC_CONCURRENT freed 3617K, 29% free 20525K/28648K, paused 4ms+5ms, total 85ms
GC_LINE = re.compile(r'^(GC_(?:CONCURRENT|FOR_M?ALLOC|EXTERNAL_ALLOC|EXPLICIT) )(freed <?\d+.)(, \d+\% free \d+./\d+., )(paused \d+ms(?:\+\d+ms)?)')



def parse_args():
  parser = argparse.ArgumentParser(description='Filter logcat by package name')
  #device
  parser.add_argument('-s', '--serial', dest='device_serial', help='Device serial number (adb -s option)')
  parser.add_argument('-d', '--device', dest='use_device', action='store_true', help='Use first device for log input (adb -d option)')
  parser.add_argument('-e', '--emulator', dest='use_emulator', action='store_true', help='Use first emulator for log input (adb -e option)')
  parser.add_argument('-c', '--clear', dest='clear_logcat', action='store_true', help='Clear the entire log before running')
  #filter
  parser.add_argument('activities', nargs='*', help='Application package name(s)')
  parser.add_argument('-n', '--current', dest='current_app', action='store_true', help='Filter logcat by current running app')
  parser.add_argument('-t', '--tag', dest='filter_tag', action='append', help='Filter output by specified tag(s)')
  parser.add_argument('-i', '--ignore-tag', dest='ignored_tag', action='append', help='Filter output by ignoring specified tag(s)')
  parser.add_argument('-a', '--all', dest='all', action='store_true', default=False, help='Print all log messages')
  #display
  parser.add_argument('-w', '--tag-width', metavar='N', dest='header_size', type=int, default=23, help='Width of the header column')
  parser.add_argument('-r', '--group-color', nargs='+', dest='cgroup_color', type=str, choices=['tag', 'pid', 'tid'], default=['tag'], help='Which column to group colors')
  parser.add_argument('-g', '--group', nargs='+', dest='cgroup_column', type=str, choices=['tag', 'pid', 'tid'], default=['tag'], help='Which column to display on group')
  parser.add_argument('-l', '--min-level', dest='min_level', type=str, choices=LOG_LEVELS+LOG_LEVELS.lower(), default='V', help='Minimum level to be displayed')
  parser.add_argument('--color-gc', dest='color_gc', action='store_true', help='Color garbage collection')
  parser.add_argument('--always-display-tags', dest='always_tags', action='store_true', help='Always display the tag name')
  parser.add_argument('--hide-process', dest='hide_proc_msg', action='store_true', default=False, help='Hide process start/end messages')
  #default
  parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__, help='Print the version number and exit')
  args = parser.parse_args()
  args.min_level = LOG_LEVELS_MAP[args.min_level.upper()]
  if len(args.activities) == 0:
    args.all = True
  return args



class LogRow():
  def __init__(self, message, pid, tid, level, tag):
    self.message = message
    self.pid = pid
    self.tid = tid
    self.level = level
    self.tag = tag

  def __getitem__(cls, x):
    return getattr(cls, x)

LogRow.RESET_TAG = LogRow(None, None, None, None, None)



class Adb():
  def __init__(self, args):
    self.args = args
    base_adb_command = ['adb']
    if args.device_serial:
      base_adb_command.extend(['-s', args.device_serial])
    if args.use_device:
      base_adb_command.append('-d')
    if args.use_emulator:
      base_adb_command.append('-e')
    self.base_adb_command = base_adb_command

  # This is a ducktype of the subprocess.Popen object
  class FakeStdinProcess():
    def __init__(self):
      self.stdout = sys.stdin
    def poll(self):
      return None

  def open(self):
    adb_command = self.base_adb_command[:]
    adb_command.append('logcat')
    adb_command.extend(['-v', 'long'])
    if sys.stdin.isatty():
      self.adb = subprocess.Popen(adb_command, stdin=PIPE, stdout=PIPE)
    else:
      self.adb = self.FakeStdinProcess()

  def clear_logcat(self):
    adb_clear_command = self.base_adb_command[:]
    adb_clear_command.append('logcat')
    adb_clear_command.append('-c')
    adb_clear = subprocess.Popen(adb_clear_command)
    while adb_clear.poll() is None:
      pass

  def get_processes(self):
    procs = set()
    ps_command = self.base_adb_command + ['shell', 'ps']
    ps_pid = subprocess.Popen(ps_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    while True:
      try:
        line = ps_pid.stdout.readline().decode('utf-8', 'replace').strip()
      except KeyboardInterrupt:
        break
      if len(line) == 0:
        break
      pid_match = PID_LINE.match(line)
      if pid_match is not None:
        pid = pid_match.group(1)
        name = pid_match.group(2).strip()
        procs.add((pid, name))
    return procs

  def get_activities(self):
    system_dump_command = self.base_adb_command + ["shell", "dumpsys", "activity", "activities"]
    system_dump = subprocess.Popen(system_dump_command, stdout=PIPE, stderr=PIPE).communicate()[0]
    return TASK_LINE.search(system_dump.decode('utf-8', 'replace')).group(1)

  def readline(self):
    return self.adb.stdout.readline().decode('utf-8', 'replace').strip()

  def poll(self):
    while self.adb.poll() is None:
      try:
        line = self.readline()
      except KeyboardInterrupt:
        break
      if len(line) == 0:
        sleep(0.01)
        continue
      bug_line = BUG_LINE.match(line)
      if bug_line is not None:
        continue
      log_line = LOG_LINE.match(line)
      if log_line is None:
        continue
      message = self.readline()
      pid, tid, level, tag = log_line.groups()
      pid = pid.strip()
      tid = tid.strip()
      level = level.strip()
      tag = tag.strip()
      return LogRow(message, pid, tid, level, tag)
    return None

  @staticmethod
  def to_pid_set(processes):
    return set(map(lambda p: p[0], processes))

  @staticmethod
  def filter_pid(processes, pick):
    # Filter pid of the process that matches the names of packages.
    return list(filter(lambda p: p[1] in pick, processes))



class Matcher():
  def __init__(self, pids, all, processes, packages):
    self.pids = pids
    self.all = all
    self.processes = processes
    self.packages = packages

  def match_packages(self, token):
    if self.all:
      return True
    if token in self.processes:
      return True
    index = token.find(':')
    match = token if index == -1 else token[:index]
    return match in self.packages

  def parse_death(self, tag, message):
    if tag != 'ActivityManager':
      return None, None
    kill = PID_KILL.match(message)
    if kill:
      pid = kill.group(1)
      package_line = kill.group(2)
      if self.match_packages(package_line) and pid in self.pids:
        return pid, package_line
    leave = PID_LEAVE.match(message)
    if leave:
      pid = leave.group(2)
      package_line = leave.group(1)
      if self.match_packages(package_line) and pid in self.pids:
        return pid, package_line
    death = PID_DEATH.match(message)
    if death:
      pid = death.group(2)
      package_line = death.group(1)
      if self.match_packages(package_line) and pid in self.pids:
        return pid, package_line
    return None, None

  def parse_start_proc(self, line):
    start = PID_START_5_1.match(line)
    if start is not None:
      line_pid, line_package, target = start.groups()
      return line_package, target, line_pid, '', ''
    start = PID_START.match(line)
    if start is not None:
      line_package, target, line_pid, line_uid, line_gids = start.groups()
      return line_package, target, line_pid, line_uid, line_gids
    start = PID_START_DALVIK.match(line)
    if start is not None:
      line_pid, line_package, line_uid = start.groups()
      return line_package, '', line_pid, line_uid, ''
    return None

  @staticmethod
  def filter_packages(activities):
    # Filter the names of packages for which to match all processes.
    return list(filter(lambda ref: ref.find(":") == -1, activities))

  @staticmethod
  def filter_processes(activities):
    # Store the name of processes to match exactly.
    named_processes = filter(lambda ref: ref.find(":") != -1, activities)
    # Convert default process names from <package>: (cli notation) to <package> (android notation) 
    # in the exact names match group.
    return list(map(lambda ref: ref if ref.find(":") != len(ref) - 1 else ref[:-1], named_processes))



class Filter(object):
  def filter(self, log_row):
    pass



class ProcessFilter(Filter):
  def __init__(self, matcher, args, procs):
    self.matcher = matcher
    self.all = args.all
    self.pids = Adb.to_pid_set(procs)
    self.app_pid = None
    for (pid, name) in procs:
      self.process_exists(name, pid)

  def process_exists(self, proc, pid):
    pass

  def process_created(self, package, target, pid, uid, gids):
    pass

  def process_destroyed(self, pid, pname):
    pass

  def filter(self, log_row):
    if not log_row:
      return None
    m = self.matcher
    start = m.parse_start_proc(log_row.message)
    if start:
      s_package, s_target, s_pid, s_uid, s_gids = start
      if m.match_packages(s_package):
        self.pids.add(s_pid)
        self.app_pid = s_pid
        self.process_created(s_package, s_target, s_pid, s_uid, s_gids)
        return LogRow.RESET_TAG # Ensure next log gets a color group printed
    dead_pid, dead_pname = m.parse_death(log_row.tag, log_row.message)
    if dead_pid:
      self.pids.remove(dead_pid)
      self.process_destroyed(dead_pid, dead_pname)
      return LogRow.RESET_TAG # Ensure next log gets a color group printed
    # Make sure the backtrace is printed after a native crash
    if log_row.tag == 'DEBUG':
      bt_line = BACKTRACE_LINE.match(log_row.message.lstrip())
      if bt_line is not None:
        log_row.message = log_row.message.lstrip()
        if self.app_pid not in self.pids:
          return None
    if not self.all and log_row.pid not in self.pids:
      return None
    return log_row



class ProcessDisplay(ProcessFilter):
  def __init__(self, matcher, console, args, procs):
    self.hide_proc_msg = args.hide_proc_msg
    self.header_size = args.header_size
    self.console = console
    ProcessFilter.__init__(self, matcher, args, procs)

  def process_exists(self, proc, pid):
    if self.hide_proc_msg: return
    c = self.console
    hdr = self.header_size
    linebuf  = '\n'
    linebuf += c.colorize(' ' * (hdr - 1), bg=c.WHITE)
    linebuf += c.indent_wrap(' Process %s (PID: %s) exists' % (proc, pid), hdr)
    linebuf += '\n'
    c.write(linebuf)

  def process_created(self, package, target, pid, uid, gids):
    if self.hide_proc_msg: return
    c = self.console
    hdr = self.header_size
    linebuf  = '\n'
    linebuf += c.colorize(' ' * (hdr - 1), bg=c.WHITE)
    linebuf += c.indent_wrap(' Process %s (PID: %s) created for %s' % (package, pid, target), hdr)
    if (len(uid.strip()) > 0 or len(gids.strip()) > 0):
      linebuf += c.colorize(' ' * (hdr - 1), bg=c.WHITE)
      linebuf += '\n UID: %s   GIDs: %s' % (uid, gids)
    linebuf += '\n'
    c.write(linebuf)

  def process_destroyed(self, pid, pname):
    if self.hide_proc_msg: return
    c = self.console
    hdr = self.header_size
    linebuf  = '\n'
    linebuf += c.colorize(' ' * (hdr - 1), bg=c.RED)
    linebuf += c.indent_wrap(' Process %s (PID: %s) ended' % (pname, pid), hdr)
    linebuf += '\n'
    c.write(linebuf)



class TagFilter(Filter):
  def __init__(self, args):
    self.ignored_tag = args.ignored_tag
    self.filter_tag = args.filter_tag
    self.min_level = args.min_level

  @staticmethod
  def __tag_in_tags_regex(tag, tags):
    return any(re.match(t, tag.strip()) for t in map(str.strip, tags))

  def filter(self, log_row):
    if not log_row:
      return None
    if log_row == LogRow.RESET_TAG:
      return log_row
    if log_row.level in LOG_LEVELS_MAP and LOG_LEVELS_MAP[log_row.level] < self.min_level:
      return None
    if self.ignored_tag and self.__tag_in_tags_regex(log_row.tag, self.ignored_tag):
      return None
    if self.filter_tag and not self.__tag_in_tags_regex(log_row.tag, self.filter_tag):
      return None
    return log_row



class ExtraLogColor(Filter):
  def __init__(self, console, args):
    c = console
    self.rules = {
      STRICT_MODE_LINE : r'%s\1%s\2%s\3%s' % (c.termcolor(c.RED), c.RESET, c.termcolor(c.YELLOW), c.RESET),
    }
    # Only enable GC coloring if the user opted-in
    if args.color_gc:
      key = GC_LINE
      val = r'\1%s\2%s\3%s\4%s' % (c.termcolor(c.GREEN), c.RESET, c.termcolor(c.YELLOW), c.RESET)
      self.rules[key] = val

  def filter(self, log_row):
    if not log_row: return None
    for matcher in self.rules:
      replace = self.rules[matcher]
      log_row.message = matcher.sub(replace, log_row.message)
    return log_row



class TagColor(Filter):
  def __init__(self, console, args):
    self.console = console
    self.header_size = args.header_size
    self.cgroup_color = args.cgroup_color
    self.cgroup_column = args.cgroup_column
    self.min_level = args.min_level
    self.always_tags = args.always_tags
    c = console

    self.last_used = [c.RED, c.GREEN, c.YELLOW, c.BLUE, c.MAGENTA, c.CYAN]

    self.known_tags = {
      'dalvikvm': c.WHITE,
      'Process': c.WHITE,
      'ActivityManager': c.WHITE,
      'ActivityThread': c.WHITE,
      'AndroidRuntime': c.CYAN,
      'jdwp': c.WHITE,
      'StrictMode': c.WHITE,
      'DEBUG': c.YELLOW,
    }

    self.tag_types = {
      'V': c.colorize(' V ', fg=c.WHITE, bg=c.BLACK),
      'D': c.colorize(' D ', fg=c.BLACK, bg=c.BLUE),
      'I': c.colorize(' I ', fg=c.BLACK, bg=c.GREEN),
      'W': c.colorize(' W ', fg=c.BLACK, bg=c.YELLOW),
      'E': c.colorize(' E ', fg=c.BLACK, bg=c.RED),
      'F': c.colorize(' F ', fg=c.BLACK, bg=c.RED),
    }
    
    self.last_cgroup = None
    self.last_cgroup_text = None
    self.last_line = ''

  def __allocate_color(self, tag):
    # this will allocate a unique format for the given tag
    # since we dont have very many colors, we always keep track of the LRU
    if tag not in self.known_tags:
      self.known_tags[tag] = self.last_used[0]
    color = self.known_tags[tag]
    if color in self.last_used:
      self.last_used.remove(color)
      self.last_used.append(color)
    return color

  def filter(self, log_row):
    if not log_row: return None

    cgroup = str.join(' ', map(lambda l: log_row[l], self.cgroup_color))
    cgroup_text = str.join(' ', map(lambda l: log_row[l], self.cgroup_column))

    canon_line = '%s;%s;%s;%s' % (cgroup, log_row.level, log_row.tag, log_row.message)
    if self.last_line == canon_line:
      return None
    self.last_line = canon_line

    if log_row == LogRow.RESET_TAG:
      self.last_cgroup = None
      self.last_cgroup_text = None
      return None

    linebuf = ''

    # right-align tag title and allocate color if needed
    w = self.header_size - 5
    c = self.console
    if w > 0:
      if cgroup_text != self.last_cgroup_text or cgroup != self.last_cgroup or self.always_tags:
        self.last_cgroup = cgroup
        self.last_cgroup_text = cgroup_text
        color = self.__allocate_color(cgroup)
        cgroup_text = cgroup_text[-w:].rjust(w)
        linebuf += c.colorize(cgroup_text, fg=color)
      else:
        linebuf += ' ' * w
      linebuf += ' '

    # write out level colored edge
    if log_row.level in self.tag_types:
      linebuf += self.tag_types[log_row.level]
    else:
      linebuf += ' ' + log_row.level[:1] + ' '

    log_row.tag = linebuf
    return log_row



class LogDisplay(ProcessFilter):
  def __init__(self, console, args):
    self.console = console
    self.header_size = args.header_size

  def filter(self, log_row):
    if not log_row: return
    c = self.console
    message = log_row.tag + ' ' + c.indent_wrap(log_row.message, self.header_size)
    c.write(message)



class Console():
  def __init__(self):
    init()
    self.isatty = sys.stdin.isatty()
    self.cstream = AnsiToWin32(sys.stderr).stream
    self.width = -1
    try:
      # Get the current terminal width
      import fcntl, termios, struct
      h, w = struct.unpack('hh', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('hh', 0, 0)))
      self.height = h
      self.width = w
    except:
      pass

  BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

  RESET = '\033[0m'

  @staticmethod
  def termcolor(fg=None, bg=None):
    codes = []
    if fg is not None: codes.append('3%d' % fg)
    if bg is not None: codes.append('10%d' % bg)
    return '\033[%sm' % ';'.join(codes) if codes else ''

  def colorize(self, message, fg=None, bg=None):
    return self.termcolor(fg, bg) + message + self.RESET if self.isatty else message

  def indent_wrap(self, message, header_size):
    if self.width == -1:
      return message
    if header_size == -1:
      return message
    message = message.replace('\t', '    ')
    wrap_area = self.width - header_size
    messagebuf = ''
    current = 0
    while current < len(message):
      next = min(current + wrap_area, len(message))
      messagebuf += message[current:next]
      if next < len(message):
        messagebuf += '\n'
        messagebuf += ' ' * header_size
      current = next
    return messagebuf

  def write(self, message):
    print(message, file=self.cstream if self.isatty else sys.stdin)



def run():
  args = parse_args()
  adb = Adb(args)
  if args.clear_logcat:
    adb.clear_logcat()
  if args.current_app:
    args.activities.append(adb.get_activities())
  processes = Matcher.filter_processes(args.activities)
  packages = Matcher.filter_packages(args.activities)
  procs = Adb.filter_pid(adb.get_processes(), processes)
  matcher = Matcher(Adb.to_pid_set(procs), args.all, processes, packages)
  console = Console()
  displayProcess = ProcessDisplay(matcher, console, args, procs)
  filterTag = TagFilter(args)
  colorTag = TagColor(console, args)
  colorExtra = ExtraLogColor(console, args)
  displayLog = LogDisplay(console, args)

  adb.open()
  while True:
    log_row = adb.poll()
    if not log_row: break
    log_row = displayProcess.filter(log_row)
    log_row = filterTag.filter(log_row)
    log_row = colorTag.filter(log_row)
    log_row = colorExtra.filter(log_row)
    displayLog.filter(log_row)

if __name__ == "__main__":
  run()
