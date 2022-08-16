# this module uploads/updates casedoc to polarion system
import datetime
import sys
import logging
try:
    from pylero.work_item import TestCase
    from pylero.document import Document
    from pylero.test_step import TestStep
    from pylero.test_steps import TestSteps
except ImportError:
    print("please install pylero in polarion operation")
    sys.exit()

try:
    from yaml import load, dump
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
log = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)

class PolarionCase:
    def __init__(self,cfg=None):
        self.project = cfg.get('project')
        self.prefix = cfg.get('prefix')
        self.document = self.prefix + cfg.get('document')
        self.space = cfg.get('space')
        self.author = cfg.get('author')
        self.parent_id = cfg.get('parent_id')
        self.casedoc = ""
        self.doc = None
        try:
            self.doc = Document(project_id=self.project, doc_with_space="{}/{}".format(self.space, self.document))
        except Exception as e:
            log.error("Cannot get document {}/{}:{}".format(self.space, self.document,e))
        try:
            if not self.doc:
                self.doc = Document.create(self.project, self.space, self.document, self.document,["testcase"],"testspecification",)
        except Exception as e:
            log.error("Cannot create document {}/{}:{}".format(self.space, self.document,e))
        if not self.doc:
            sys.exit(1)
        log.info("Document found:{}".format(self.doc.title))

    def add_new(self):
        '''
        add a new case
        casedoc is os-tests test case's yaml docstring
        '''
        tc = TestCase()
        tc.title = self.prefix + self.casedoc.get('case_name')
        #tc.description = self.casedoc.get('description')
        tc.description = dump(self.casedoc).replace('\n','</br>')
        maintainer = self.casedoc.get('maintainer')
        if maintainer and '@' in maintainer:
            maintainer = maintainer[:maintainer.index('@')]
        tc.author = maintainer or self.author
        tc.customerscenario = self.casedoc.get("is_customer_case") or False
        tc.tcmsbug = str(self.casedoc.get("bugzilla_id"))
        tc.caseimportance = self.casedoc.get("Importance") or 'medium'
        tc.status="approved"
        tc.caselevel="component"
        tc.caseautomation="automated"
        tc.caseposneg="positive"
        tc.subsystemteam="sst_virtualization_cloud"
        tc.testtype="functional"
        steps = TestSteps()
        steps.keys = ["step", "expectedResult"]
        step1 = TestStep()
        step1.values = [self.casedoc.get("key_steps") or '', self.casedoc.get("expect_result") or '']
        steps.steps = [step1]
        tc.test_steps = steps
        wi = self.query_case()
        if wi:
            log.info("Exists workitem with title found {}".format(self.prefix + self.casedoc.get('case_name')))
            return False
        try:
            new_wi = self.doc.create_work_item(self.parent_id, tc)
            new_tc = TestCase(work_item_id=new_wi.work_item_id)
            new_tc.status = "approved"
            new_tc.update()
        except Exception as e:
            log.error("Fail to add new case: {}. Exception: {}".format(self.prefix + self.casedoc.get("case_name", ''), str(e)))
            raise
        log.info("{}: {} is created.".format(new_wi.work_item_id, tc.title))
        return True

    def update_case(self):
        '''
        update an exists case
        casedoc is os-tests test case's yaml docstring
        '''
        wi = self.query_case()
        if not wi:
            log.info("Not found workitem with title {}".format(self.prefix + self.casedoc.get('case_name')))
            return False
        tc = TestCase(project_id = self.project, work_item_id=wi[0].work_item_id)
        global changed
        changed = False
        global msg
        msg = ''
        def _update_item(item, key, default_value=None):
            global changed
            global msg
            if item != (self.casedoc.get(key) or default_value):
                item = self.casedoc.get(key) or default_value
                msg += "{}: {} is changed to {}\n".format(tc.work_item_id, key, item)
                changed = True
            return item
        if tc.description != dump(self.casedoc).replace('\n','</br>'):
            tc.description = dump(self.casedoc).replace('\n','</br>')
            changed = True
            log.info('casedoc changed, syncing......')
        #tc.description = _update_item(tc.description, "Description")
        tc.customerscenario = _update_item(tc.customerscenario, "Customer Scenario", False)
        # Author cannot be updated
        # tc.author = _update_item(tc.author, "Author", self.default_author)
        tc.caseimportance = _update_item(tc.caseimportance, "Importance", "medium")
        tc.status = _update_item(tc.status, "Status", "approved")
        if tc.test_steps.steps:
            if tc.test_steps.steps[0].values[0].content != self.casedoc.get("key_steps") or \
               tc.test_steps.steps[0].values[1].content != self.casedoc.get("Expected Result"):
                step1 = TestStep()
                step1.values = [self.casedoc.get("key_steps") or '', self.casedoc.get("Expected Result") or '']
                tc.set_test_steps([step1])
                msg += "{}: Test step is changed.\n".format(tc.work_item_id)
        # TCMS Bugs can only append, and need de-duplication
        if self.casedoc.get('bugzilla_id'):
            tcmsbug_list = tc.tcmsbug.split(',') if tc.tcmsbug else []
            tcmsbug_list_new = list(set([x.strip(' ') for x in tcmsbug_list]))
            for bug_id in str(self.casedoc.get('bugzilla_id', '')).split(','):
                bug_id = bug_id.strip(' ')
                if bug_id not in tcmsbug_list_new:
                    tcmsbug_list_new.append(bug_id)
                    changed = True
                    msg += "{}: {} is added to tcmsbugs.\n".format(tc.work_item_id, bug_id)
            tc.tcmsbug = ','.join(tcmsbug_list_new)
        if changed:
            try:
                tc.update()
                log.info('Updated successfully!')
            except Exception as e:
                log.error('Failed to update {}: {}. Exception: {}'.format(tc.work_item_id, tc.title, str(e)))
        if msg:
            log.info(msg)

    def query_case(self):
    
        fields = ['work_item_id',
                      'title',
                      'author',
                      'created']
        title = self.prefix + self.casedoc.get('case_name')
        #default_project = 'RHELVIRT'
        #query = 'project.id:{} AND title:{}'.format(default_project,title)
        query = 'title:"{}"'.format(title)
        workitem_list = TestCase.query(query, fields)
        return workitem_list