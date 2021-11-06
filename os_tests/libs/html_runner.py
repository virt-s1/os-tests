from unittest import TextTestResult
from unittest.signals import registerResult
from . import utils_lib
import sys
import time
import warnings
import string
import os
from jinja2 import Template, FileSystemLoader, Environment, PackageLoader, select_autoescape

class Result():
    def __init__(self):
        self.case_pass = 0
        self.case_fail = 0
        self.case_skip = 0
        self.case_error = 0
        self.run_time = 0
        self.table_rows = []

class HTMLTemp():
    def __init__(self, logfile):
        self.result = Result()
        self.logfile = logfile

    def generated_report(self):
        if os.path.exists(self.logfile):
            os.unlink(self.logfile)
        self.result.total = self.result.case_pass + self.result.case_error + self.result.case_fail + self.result.case_skip
        if self.result.total - self.result.case_skip > 0:
            self.result.pass_rate = self.result.case_pass/(self.result.total - self.result.case_skip) * 100
        else:
            self.result.pass_rate = 0
        self.result.run_time = format(self.result.run_time,'0.2f')
        self.result.pass_rate = format(self.result.pass_rate,'0.2f')

        file_loader = PackageLoader('os_tests','templates')
        env = Environment(loader=file_loader)
        template = env.get_template('sum.html')
        output = template.render(result=self.result)
        with open(self.logfile, 'w+') as fh:
            print(output, file=fh)
        print("summary in html: {}".format(os.path.realpath(self.logfile)))

class _WritelnDecorator(object):
    """Used to decorate file-like objects with a handy 'writeln' method"""
    def __init__(self,stream):
        self.stream = stream

    def __getattr__(self, attr):
        if attr in ('stream', '__getstate__'):
            raise AttributeError(attr)
        return getattr(self.stream,attr)

    def writeln(self, arg=None):
        if arg:
            self.write(arg)
        self.write('\n') # text-mode streams translate to \r\n if needed

class HTMLTestRunner(object):
    """A test runner class that displays results in textual form.

    It prints out the names of tests as they are run, errors as they
    occur, and a summary of the results at the end of the test run.
    """
    resultclass = TextTestResult

    def __init__(self, stream=None, descriptions=True, verbosity=1,
                 failfast=False, buffer=False, resultclass=None, warnings=None,
                 *, tb_locals=False):
        """Construct a TextTestRunner.

        Subclasses should accept **kwargs to ensure compatibility as the
        interface changes.
        """
        if stream is None:
            stream = sys.stderr
        self.stream = _WritelnDecorator(stream)
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.failfast = failfast
        self.buffer = buffer
        self.tb_locals = tb_locals
        self.warnings = warnings
        if resultclass is not None:
            self.resultclass = resultclass

    def _makeResult(self):
        return self.resultclass(self.stream, self.descriptions, self.verbosity)

    def run(self, test, logdir=None):
        "Run the given test case or test suite."
        result = self._makeResult()
        registerResult(result)
        result.failfast = self.failfast
        result.buffer = self.buffer
        result.tb_locals = self.tb_locals
        with warnings.catch_warnings():
            if self.warnings:
                # if self.warnings is set, use it to filter all the warnings
                warnings.simplefilter(self.warnings)
                # if the filter is 'default' or 'always', special-case the
                # warnings from the deprecated unittest methods to show them
                # no more than once per module, because they can be fairly
                # noisy.  The -Wd and -Wa flags can be used to bypass this
                # only when self.warnings is None.
                if self.warnings in ['default', 'always']:
                    warnings.filterwarnings('module',
                            category=DeprecationWarning,
                            message=r'Please use assert\w+ instead.')
            startTime = time.perf_counter()
            startTestRun = getattr(result, 'startTestRun', None)
            if startTestRun is not None:
                startTestRun()
            all_case_name = [ ts.id() for ts in test ]
            for ts in test:
                logdir = ts.params['results_dir']
                break
            try:
                test(result)
            finally:
                stopTestRun = getattr(result, 'stopTestRun', None)
                if stopTestRun is not None:
                    stopTestRun()
            stopTime = time.perf_counter()
        timeTaken = stopTime - startTime
        sum_html = logdir + '/sum.html'
        sum_txt = logdir + '/sum.log'
        if os.path.exists(sum_txt):
            os.unlink(sum_txt)
        html_sum = HTMLTemp(sum_html)
        html_sum.result.run_time = timeTaken
        all_case_name.sort()
        id = 0
        for case in all_case_name:
            id += 1
            is_pass = True
            os.chdir(logdir)
            debug_log = "debug/" + case + '.debug'
            for ts, err in result.failures:
                if case == ts.id():
                    is_pass = False
                    html_sum.result.case_fail += 1
                    html_sum.result.table_rows.append((id, case, 'FAIL', err, debug_log))
                    with open(debug_log, 'a+') as fh:
                        fh.write(err)
                        fh.write('{} - FAIL'.format(case))
                    with open(sum_txt, 'a+') as fh:
                        fh.write('case: {} - FAIL\n'.format(case))
                        fh.write('info: {}\n'.format(err))
                    break
            if not is_pass:
                continue
            for ts, err in result.errors:
                if case == ts.id():
                    is_pass = False
                    html_sum.result.case_error += 1
                    html_sum.result.table_rows.append((id, case, 'ERROR', err, debug_log))
                    with open(debug_log, 'a+') as fh:
                        fh.write(err)
                        fh.write('{} - ERROR'.format(case))
                    with open(sum_txt, 'a+') as fh:
                        fh.write('case: {} - ERROR\n'.format(case))
                        fh.write('info: {}\n'.format(err))
                    break
            if not is_pass:
                continue
            for ts, reason in result.skipped:
                if case == ts.id():
                    is_pass = False
                    html_sum.result.case_skip += 1
                    html_sum.result.table_rows.append((id, case, 'SKIP', reason, debug_log))
                    with open(debug_log, 'a+') as fh:
                        fh.write(reason)
                        fh.write('{} - SKIP'.format(case))
                    with open(sum_txt, 'a+') as fh:
                        fh.write('case: {} - SKIP\n'.format(case))
                        fh.write('info: {}\n'.format(reason))
                    break
            if not is_pass:
                continue
            html_sum.result.case_pass += 1
            html_sum.result.table_rows.append((id, case, 'PASS', '', debug_log))
            with open(debug_log, 'a+') as fh:
                fh.write('{} - PASS'.format(case))
            with open(sum_txt, 'a+') as fh:
                fh.write('case: {} - PASS\n'.format(case))
        if hasattr(result, 'separator2'):
            self.stream.writeln(result.separator2)
        html_sum.generated_report()
        self.stream.writeln("summary in text: {}".format(os.path.realpath(sum_txt)))
        #result.printErrors()
        if hasattr(result, 'separator2'):
            self.stream.writeln(result.separator2)
        run = result.testsRun
        self.stream.writeln("Ran %d test%s in %.3fs" %
                            (run, run != 1 and "s" or "", timeTaken))
        self.stream.writeln()

        expectedFails = unexpectedSuccesses = skipped = 0
        try:
            results = map(len, (result.expectedFailures,
                                result.unexpectedSuccesses,
                                result.skipped))
        except AttributeError:
            pass
        else:
            expectedFails, unexpectedSuccesses, skipped = results

        infos = []
        if not result.wasSuccessful():
            self.stream.write("FAILED")
            failed, errored = len(result.failures), len(result.errors)
            if failed:
                infos.append("failures=%d" % failed)
            if errored:
                infos.append("errors=%d" % errored)
        else:
            self.stream.write("OK")
        if skipped:
            infos.append("skipped=%d" % skipped)
        if expectedFails:
            infos.append("expected failures=%d" % expectedFails)
        if unexpectedSuccesses:
            infos.append("unexpected successes=%d" % unexpectedSuccesses)
        if infos:
            self.stream.writeln(" (%s)" % (", ".join(infos),))
        else:
            self.stream.write("\n")
        return result
