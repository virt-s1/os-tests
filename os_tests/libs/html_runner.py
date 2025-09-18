from unittest import TextTestResult
from unittest.signals import registerResult
from . import utils_lib
import sys
import time
import warnings
import string
import contextlib
import os
from importlib.resources import files
from jinja2 import Template, FileSystemLoader, Environment, select_autoescape
import json
from os_tests.libs.utils_lib import init_args
import re

class ResultSummary:
    '''
    The class is for test result summary.
    '''
    def __init__(self):
        self.total = 0
        self.pass_rate = 0
        self.case_pass = 0
        self.case_fail = 0
        self.case_skip = 0
        self.case_error = 0
        self.run_time = 0
        self.table_rows = []
        self.node_info = None
        self.release_version = None
        self.run_title = None
        self.run_date = time.asctime()
        self.comment = ''

    def compute_totals(self):
        self.total = self.case_pass + self.case_error + self.case_fail + self.case_skip
        if self.total - self.case_skip > 0:
            self.pass_rate = self.case_pass / (self.total - self.case_skip) * 100


def generated_report(logfile, template_name, result):
    if os.path.exists(logfile):
        os.unlink(logfile)

    try:
        file_loader = FileSystemLoader(str(files("os_tests").joinpath("templates")))
    except:
        try:
            from jinja2 import PackageLoader
            file_loader = PackageLoader("os_tests", "templates")
        except:
            print("Error in loading templates:{}".format(err))
            sys.exit(1)
    env = Environment(loader=file_loader)
    template = env.get_template(template_name)
    if template_name.endswith('xml'):
        from xml.sax.saxutils import escape
        for row in result.table_rows:
            # escap special character(<&>) in output
            for i,v in enumerate(row):
                if isinstance(row[i], str):
                    row[i] = escape(v)
    output = template.render(result=result)
    with open(logfile, "w+") as fh:
        fh.write(output)
    print("{} generated".format(os.path.realpath(logfile)))

@contextlib.contextmanager
def pushd(new_dir):
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)

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

class HTMLTestResult(TextTestResult):
    def __init__(self, stream, descriptions, verbosity, *, durations=None):
        """Construct a TextTestResult. Subclasses should accept **kwargs
        to ensure compatibility as the interface changes."""
        super(HTMLTestResult, self).__init__(stream, descriptions, verbosity)
        self.planned = 0

    def getDescription(self, test):
        # do not return the docs content to make output clean
        #doc_first_line = test.shortDescription()
        #if self.descriptions and doc_first_line:
        #    return '\n'.join((str(test), doc_first_line))
        #else:
        ret = str(test)
        if self.testsRun:
            ret = "{} - {}/{}".format(ret, self.testsRun, self.planned )
        return ret

class HTMLTestRunner(object):
    """A test runner class that displays results in html form.

    While printing out the names of tests as they are run, errors as they
    occur, and a summary of the results at the end of the test run. It
    also generates html report for reading and link to related debug logs.
    """
    resultclass = HTMLTestResult

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
        self.comment = ''
        if resultclass is not None:
            self.resultclass = resultclass

    def _makeResult(self):
        return self.resultclass(self.stream, self.descriptions, self.verbosity)

    def run(self, test, logdir=None):
        "Run the given test case or test suite."
        result = self._makeResult()
        test_result_summary = ResultSummary()
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
            id = 0
            all_case_name = [ ts.id() for ts in test ]
            result.planned = len(all_case_name)
            for ts in test:
                logdir = ts.params['results_dir']
                test_result_summary.comment = ts.params.get('comment')
                if not os.path.exists(logdir):
                    os.makedirs(logdir,exist_ok=True)
                results_dir = logdir + '/results'
                if not os.path.exists(results_dir):
                    os.makedirs(results_dir,exist_ok=True)
                sum_txt = results_dir + '/sum.log'
                case_status = None
                case_reason = None
                id += 1
                case_startTime = time.perf_counter()
                startTestRun = getattr(result, 'startTestRun', None)
                if startTestRun is not None:
                    startTestRun()
                try:
                    ts(result)
                finally:
                    stopTestRun = getattr(result, 'stopTestRun', None)
                    if stopTestRun is not None:
                        stopTestRun()
                    ts.duration = timeTaken = round(time.perf_counter() - case_startTime, 3)
                test_class_name = ts.__class__.__name__
                case_dir = '.'.join([test_class_name, ts.id()])
                debug_dir = logdir + "/attachments/" + case_dir
                if not os.path.exists(debug_dir):
                    os.makedirs(debug_dir,exist_ok=True)
                debug_log = "../attachments/" + case_dir + '/' + ts.id() + '.debug'
                with pushd(results_dir):
                    mapped_result = {'FAIL':result.failures, 'ERROR':result.errors, 'SKIP':result.skipped}
                    for status in mapped_result.keys():
                        for ts_finished, reason in mapped_result[status]:
                            if ts_finished == ts:
                                if status == 'FAIL':
                                    test_result_summary.case_fail += 1
                                if status == 'ERROR':
                                    test_result_summary.case_error += 1
                                if status == 'SKIP':
                                    test_result_summary.case_skip += 1
                                case_status = status
                                case_reason = reason
                                try:
                                    ts.log.info('{0}case done{0}'.format('-'*20))
                                    ts.log.info(reason)
                                    ts.log.info('{} - {}'.format(ts.id(), status))
                                except Exception as err:
                                    with open(debug_log, 'a+') as fh:
                                        fh.write('{0}case done{0}'.format('-'*20))
                                        fh.write(reason)
                                        fh.write('{} - {}'.format(ts.id(), status))
                                if status in ['ERROR', 'FAIL'] and hasattr(ts, 'log') and ts_finished.params.get('enable_auto_result_check'):
                                    ts.log.info("-----enable_auto_result_check enabled, auto check result--------")
                                    src_content = ''
                                    with open(debug_log, 'r') as fh:
                                        src_content = fh.read()
                                    ret, _ = utils_lib.find_word(ts, src_content, case=ts.id())
                                    case_reason = "{} IS_KNOWN:{} Please check auto analyze details in debug log".format(case_reason, not ret)
                                break
                    if not case_status:
                        test_result_summary.case_pass += 1
                        with open(debug_log, 'a+') as fh:
                            fh.write('{} - PASS'.format(ts.id()))
                        case_status = 'PASS'
                        case_reason = ''
                test_result_summary.table_rows.append([id, ts.id(), case_status, case_reason, ts.duration, debug_log, test_class_name])
                with open(sum_txt, 'a+') as fh:
                    fh.write('case: {} - {}\n'.format(ts.id(),case_status))
                    if case_reason:
                        fh.write('info: {}\n'.format(case_reason))
            stopTime = time.perf_counter()
        timeTaken = round(stopTime - startTime, 3)
        test_result_summary.run_time = timeTaken
        all_case_name.sort()
        id = 0
        for case in all_case_name:
            id += 1
            is_pass = True
            #  os.chdir(logdir)
            debug_log = "../attachments/" + case + '.debug'
        if hasattr(result, 'separator2'):
            print(result.separator2)
        test_result_summary.compute_totals()
        node_info_file = "{}/attachments/node_info".format(logdir)
        if os.path.exists(node_info_file):
            with open(node_info_file) as fh:
                test_result_summary.node_info = fh.read()
        results_dir = logdir + '/results'
        if not os.path.exists(results_dir):
            os.mkdir(results_dir)
        sum_html = os.path.join(results_dir, "sum.html")
        generated_report(sum_html, "sum.html", test_result_summary)
        sum_junit = os.path.join(results_dir, "sum.xml")
        generated_report(sum_junit, "sum.xml", test_result_summary)
        sum_json = os.path.join(results_dir, "sum.json")
        generated_report(sum_json, "sum.json", test_result_summary)
        print("{} generated".format(os.path.realpath(sum_txt)))
        # Generate sum_polarion.xml for Polarion if there is --tc tc_file.json
        args = init_args()
        tc_json_path = args.tc_file
        if tc_json_path and os.path.exists(tc_json_path):
            # Parse node_info to fill in some Polarion fields
            if os.path.exists(node_info_file):
                with open(node_info_file) as fh:                    
                    node_info_content = fh.read()
                    test_result_summary.node_info = node_info_content
                    # Parse the release_version in node_info
                    match = re.search(r"release_version:\s*([\d.]+)", node_info_content)
                    if match:
                        version_str = match.group(1)
                        version_plannedin = version_str.replace(".", "_") + "_ga"
                        test_result_summary.release_version = version_plannedin
                    else:
                        test_result_summary.release_version = "UNKNOWN"
                    # Parse run_title in node_info
                    kernel_version = re.search(r"kernel_version:\s*([^\n]+)", node_info_content)
                    product_name = re.search(r"product_name:\s*([^\n]+)", node_info_content)
                    release_name = re.search(r"release_name:\s*([^\n]+)", node_info_content)
                    release_version = re.search(r"release_version:\s*([^\n]+)", node_info_content)
                    sys_vendor = re.search(r"sys_vendor:\s*([^\n]+)", node_info_content)

                    kernel_version = kernel_version.group(1).strip() if kernel_version else "UNKNOWN"
                    product_name = product_name.group(1).strip() if product_name else "UNKNOWN"
                    release_name = release_name.group(1).strip() if release_name else "UNKNOWN"
                    release_version = release_version.group(1).strip() if release_version else "UNKNOWN"
                    sys_vendor = sys_vendor.group(1).strip() if sys_vendor else "UNKNOWN"
                    # Format run_title
                    test_result_summary.run_title = (
                        f"os-tests for {kernel_version} of {release_name} {release_version} "
                        f"on {sys_vendor} {product_name}"
                    )
            # Load tc_file.json mapping
            with open(tc_json_path, 'r', encoding='utf-8') as f:
                tc_map = json.load(f)
            title2wid = {tc['title']: tc['work_item_id'] for tc in tc_map}
            # Append work_item_id to each row for template
            for row in test_result_summary.table_rows:
                title = row[1]
                row.append(title2wid.get(title, "UNKNOWN"))
            sum_polarion = os.path.join(results_dir, "sum_polarion.xml")
            generated_report(sum_polarion, "sum_polarion.xml", test_result_summary)
        #result.printErrors()
        if hasattr(result, 'separator2'):
            print(result.separator2)
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
