#! /usr/bin/env python3
# this module uploads/updates casedoc to polarion system
import argparse
import datetime
from doctest import DocTestFinder
import os
import sys
import logging
from collections import OrderedDict
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
log = logging.getLogger(__name__)
LOG_FORMAT = '%(levelname)s:%(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

class PolarionCase:
    def __init__(self,casedoc=None, project=None, prefix='', document='', space=None, parent_id=None, force=False):
        self.casedoc = casedoc
        self.project = project
        self.prefix = prefix
        self.document = self.prefix + document
        self.space = space
        self.parent_id = parent_id
        self.polarion_doc = None
        # ignore health check result and force update
        self.force_update = force
        self.verify_pass = verify_doc(casedoc=self.casedoc)
        try:
            self.polarion_doc = Document(project_id=self.project, doc_with_space="{}/{}".format(self.space, self.document))
        except Exception as e:
            log.error("Cannot get document {}/{}:{}".format(self.space, self.document,e))
        try:
            if not self.polarion_doc:
                self.polarion_doc = Document.create(self.project, self.space, self.document, self.document,["testcase"],"testspecification",)
        except Exception as e:
            log.error("Cannot create document {}/{}:{}".format(self.space, self.document,e))
        if not self.polarion_doc:
            sys.exit(1)
        log.info("Document found:{}".format(self.polarion_doc.title))
        self.old_case_dict = self.get_old_case_dict()
        self.title = self.prefix + self.casedoc.get('case_name')

    def add_new(self):
        '''
        add a new case
        casedoc is os-tests test case's yaml docstring
        '''
        if not self.verify_pass:
            if not self.force_update:
                log.info('please check your casedoc')
                return False
            else:
                log.info('force add new to polarion')

        try:
            tc = TestCase()
            tc.title = self.title
            #tc.description = self.casedoc.get('description')
            if isinstance(self.casedoc,OrderedDict):
                tc.description = ''
                for key in self.casedoc:
                    tc.description += "{}:{}</br>".format(key, self.casedoc.get(key))
            else:
                tc.description = dump(self.casedoc).replace('\n','</br>')
            maintainer = self.casedoc.get('maintainer')
            if maintainer and '@' in maintainer:
                maintainer = maintainer[:maintainer.index('@')]
            elif not maintainer:
                maintainer = 'linl'
            tc.author = maintainer
            tc.customerscenario = self.casedoc.get("is_customer_case") or False
            tc.tcmsbug = str(self.casedoc.get("bug_id")) or ''
            tc.caseimportance = self.casedoc.get("importance") or 'medium'
            tc.status = "approved"
            if self.casedoc.get("case_status"):
                tc.status = self.casedoc.get("case_status").lower()
            tc.caselevel= self.casedoc.get("test_level") or "component"
            tc.caseautomation=self.casedoc.get("automation_drop_down") or "automated"
            tc.caseposneg="positive"
            tc.subsystemteam=self.casedoc.get("subsystem_team") or "rhel-virt-cloud"
            tc.testtype = "functional"
            if self.casedoc.get("test_type"):
                tc.testtype = self.casedoc.get("test_type").lower()
            #tc.hyperlinks=self.casedoc.get("automation_field")
            steps = TestSteps()
            steps.keys = ["step", "expectedResult"]
            step1 = TestStep()
            step1.values = [self.casedoc.get("key_steps") or '', self.casedoc.get("expect_result") or '']
            steps.steps = [step1]
            tc.test_steps = steps
        except Exception as err:
            log.error("Init value:{}".format(err))
            log.info("case_status:{},type:{}".format(tc.status, tc.testtype))
            return False
        wi = self.is_exists()
        if wi:
            log.info("Exists workitem with title found {}".format(self.title))
            return False
        try:
            new_wi = self.polarion_doc.create_work_item(self.parent_id, tc)
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
        if not self.verify_pass:
            if not self.force_update:
                log.info('please check your casedoc')
                return False
            else:
                log.info('force update to polarion')
        wi = self.is_exists()
        if not wi:
            log.info("Not found workitem with title {}".format(self.title))
            self.add_new()
            return False
        #tc = TestCase(project_id=self.project, work_item_id=wi[0].work_item_id)
        tc = TestCase(project_id=self.project, work_item_id=self.old_case_dict.get(self.title))
        global changed
        changed = False
        global msg
        msg = ''
        def _update_item(item, key, default_value=None):
            global changed
            global msg
            new_value = self.casedoc.get(key)
            if key == 'maintainer' and new_value and '@' in new_value:
                new_value = new_value[:new_value.index('@')]
            if key == 'automation_field' and new_value:
                new_value = [{'Test Script': new_value}]
            if key == 'test_type':
                if new_value:
                    new_value = new_value.lower()
                else:
                    new_value = 'functional'
            if key == 'case_status':
                if new_value:
                    new_value = new_value.lower()
                else:
                    new_value = "approved"
            try:
                if item != new_value or default_value:
                    item = new_value or default_value
                    msg += "{}: {} is changed to {}\n".format(tc.work_item_id, key, item)
                    changed = True
            except Exception as err:
                log.error("Init value:{}".format(err))
                log.info("item:{} new:{}, default:{} casename:{}".format(item,new_value, default_value, self.casedoc.get('case_name')))
            return item
        if isinstance(self.casedoc,OrderedDict):
            tmp_description = ''
            for key in self.casedoc:
                tmp_description += "{}:{}</br>".format(key, self.casedoc.get(key))
        else:
            tmp_description = dump(self.casedoc).replace('\n','</br>')
        if tc.description != tmp_description:
            tc.description = tmp_description
            changed = True
            log.info('casedoc changed, syncing......')
        #tc.description = _update_item(tc.description, "Description")
        tc.customerscenario = _update_item(tc.customerscenario, "is_customer_case", False)
        # Author cannot be updated
        # tc.author = _update_item(tc.author, "Author", self.default_author)
        tc.caseimportance = _update_item(tc.caseimportance, "importance", "medium")
        tc.status = _update_item(tc.status, "case_status", "approved")
        maintainer = self.casedoc.get('maintainer')
        if maintainer and '@' in maintainer:
            maintainer = maintainer[:maintainer.index('@')]
        tc.author = _update_item(tc.author, "maintainer", "")
        tc.tcmsbug = _update_item(tc.tcmsbug, "bug_id", '')
        tc.caselevel = _update_item(tc.caselevel, "test_level", 'component')
        tc.caseautomation = _update_item(tc.caselevel, "automation_drop_down", 'automated')
        tc.caseposneg="positive"
        tc.subsystemteam = _update_item(tc.subsystemteam, "subsystem_team", "rhel-virt-cloud")
        tc.testtype = _update_item( tc.testtype, "test_type", "functional")
        #tc.hyperlinks= _update_item( tc.hyperlinks, "automation_field", "")
    
        if tc.test_steps.steps:
            if tc.test_steps.steps[0].values[0].content != self.casedoc.get("key_steps") or \
               tc.test_steps.steps[0].values[1].content != self.casedoc.get("expected_result"):
                step1 = TestStep()
                step1.values = [self.casedoc.get("key_steps") or '', self.casedoc.get("expected_result") or '']
                tc.set_test_steps([step1])
                msg += "{}: Test step is changed.\n".format(tc.work_item_id)
        # TCMS Bugs can only append, and need de-duplication
        if self.casedoc.get('bug_id'):
            tcmsbug_list = tc.tcmsbug.split(',') if tc.tcmsbug else []
            tcmsbug_list_new = list(set([x.strip(' ') for x in tcmsbug_list]))
            for bug_id in str(self.casedoc.get('bug_id', '')).split(','):
                bug_id = bug_id.strip(' ')
                if bug_id not in tcmsbug_list_new:
                    tcmsbug_list_new.append(bug_id)
                    changed = True
                    msg += "{}: {} is added to tcmsbugs.\n".format(tc.work_item_id, bug_id)
            tc.tcmsbug = ','.join(tcmsbug_list_new)
        update_case_hyperlinks = True
        if len(tc.hyperlinks) > 0:
            # Check if the hyperlink exists
            for i in range(len(tc.hyperlinks)):
                if tc.hyperlinks[i].role == "testscript" and \
                   tc.hyperlinks[i].uri == self.casedoc.get("automation_field"):
                   update_case_hyperlinks = False
                   break
        if update_case_hyperlinks:
            #_update_item( tc.hyperlinks, "automation_field")
            add_hyperlink = tc.add_hyperlink(self.casedoc.get("automation_field"),"testscript")
            if add_hyperlink:
                changed = True
                print("Add hyperlink for case {}".format(tc.work_item_id))
        if changed:
            try:
                tc.update()
                log.info('Updated successfully!')
            except Exception as e:
                log.error('Failed to update {}: {}. Exception: {}'.format(tc.work_item_id, tc.title, str(e)))
        if msg:
            log.info(msg)

    
    def get_old_case_dict(self):
        old_case_dict = {}
        wi_list= self.polarion_doc.get_work_items(None, True, ['work_item_id', 'title', 'type'])
        for wi in wi_list:
            if wi.type == "testcase":
                old_case_dict[wi.title] = wi.work_item_id
        return old_case_dict

    def is_exists(self):
        return self.title in self.old_case_dict

    def query_case(self):
        #doc.get_work_items
        #tc.linked_work_items[1].role
    
        fields = ['work_item_id',
                      'title',
                      'author',
                      'created']
        #default_project = 'RHELVIRT'
        #query = 'project.id:{} AND title:{}'.format(default_project,title)
        query = 'title:"{}"'.format(self.title)
        workitem_list = TestCase.query(query, fields)
        return workitem_list

def verify_doc(casedoc=None):
    is_doc_ok = True
    doc_fields = [
                    {
                        'name':'case_name',
                        'is_must':True,
                        'default':None,
                        'et_require':False
                    },
                    {
                        'name':'case_tags',
                        'is_must':False,
                        'default':None,
                        'et_require':False
                    },
                    {
                        'name':'case_status',
                        'is_must':True,
                        'default':'approved',
                        'et_require':True
                    },
                    {
                        'name':'title',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'importance',
                        'is_must':True,
                        'default':'medium',
                        'et_require':True
                    },
                    {
                        'name':'subsystem_team',
                        'is_must':True,
                        'default':'rhel-virt-cloud',
                        'et_require':True
                    },
                    {
                        'name':'automation_drop_down',
                        'is_must':True,
                        'default':'automated',
                        'et_require':True
                    },
                    {
                        'name':'linked_work_items',
                        'is_must':True,
                        'default':'TBD',
                        'et_require':True
                    },
                    {
                        'name':'automation_field',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'setup_teardown',
                        'is_must':False,
                        'default':'no special requirement',
                        'et_require':True
                    },
                    {
                        'name':'environment',
                        'is_must':False,
                        'default':'no special requirement',
                        'et_require':True
                    },
                    {
                        'name':'component',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'bug_id',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'is_customer_case',
                        'is_must':True,
                        'default':False,
                        'et_require':True
                    },
                    {
                        'name':'testplan',
                        'is_must':True,
                        'default':None,
                        'et_require':False
                    },
                    {
                        'name':'test_type',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'test_level',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'maintainer',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'description',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'key_steps',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'expected_result',
                        'is_must':True,
                        'default':None,
                        'et_require':True
                    },
                    {
                        'name':'debug_want',
                        'is_must':False,
                        'default':None,
                        'et_require':False
                    }
                ]
    
    log.info("-"*20)
    log.info("verifying {}".format(dump(casedoc)))
    for item in doc_fields:
        if casedoc.get(item.get('name')) == None:
            msg = 'missing {}'.format(item.get('name'))
            if item.get('default'):
                casedoc[item.get('name')] = item.get('default')
                msg = '{}, set it to default {}'.format(msg, item.get('default'))
            log.warning('{} is_must:{} et_require:{}'.format(msg, item.get('is_must'), item.get('et_require')))
            is_doc_ok = False
    return is_doc_ok

def load_file(doc_file=None):
    if not doc_file:
        log.warning('doc_file is required')
        return None
    if not os.path.exists(doc_file):
        log.warning('{} not found'.format(doc_file))
        return None
    doc_types = ('yaml','yml','csv')
    if not doc_file.endswith(doc_types):
        log.warning("expected file in {} format".format(doc_types))
        return None
    if doc_file.endswith(('yaml','yml')):
        log.info('yaml file detected')
        try:
            from yaml import load, dump
            from yaml import CLoader as Loader, CDumper as Dumper
        except ImportError:
            from yaml import Loader, Dumper
        try:
            with open(doc_file,'r') as fh:
                doc_contents = load(fh, Loader=Loader)
        except Exception as e:
            log.warning('read failed:{}'.format(e))
            return None
        cases = []
        for key in doc_contents.keys():
            cases.append(doc_contents.get(key))
        doc_contents = cases

    if doc_file.endswith('csv'):
        log.info('csv file detected')
        import csv
        try:
            cases = []
            with open(doc_file) as fh:
                csv_reader = csv.DictReader(fh)
                for row in csv_reader:
                    cases.append(row)
                #for row in csv_data:
                #    print('{}{}'.format(row['head1'],row['head2']))
            doc_contents = cases
        except Exception as e:
            log.warning('read failed:{}'.format(e))
            return None
    return doc_contents

def main():
    args_parser = argparse.ArgumentParser(description='a simple tool interacts with polarion')
    args_parser.add_argument('--verifydoc', dest='verify_doc', action='store_true', help='verify or show case doc only, require --docfile', required=False)
    args_parser.add_argument('--uploaddoc', dest='upload_doc', action='store_true', help='verify and upload doc to polarion', required=False)
    args_parser.add_argument('--deletedoc', dest='delete_doc', action='store_true', help='delete document only', required=False)
    args_parser.add_argument('--force', dest='is_force', action='store_true', help='ignore any fail verify result and continue to upload', required=False)
    args_parser.add_argument('--docfile', dest='doc_file', default=None, action='store',
                    help='doc file in yaml or csv', required=False)
    args_parser.add_argument('--project', dest='project', default=None, action='store',
                    help='polarion project name, eg. RHELVIRT', required=False)
    args_parser.add_argument('--prefix', dest='prefix', default='', action='store',
                    help='prefix to add into doc name and case name, optional', required=False)
    args_parser.add_argument('--document', dest='document', default='', action='store',
                    help='polarion document name, will create new if not exist', required=False)
    args_parser.add_argument('--space', dest='space', default=None, action='store',
                    help='polarion space name, eg VirtCloudQE', required=False)
    args_parser.add_argument('--parent', dest='parent_id', default=None, action='store',
                    help='specify parent id if have', required=False)

    args = args_parser.parse_args()
    doc_contents = None
    if args.doc_file:
        if not os.path.exists(args.doc_file):
            log.info("{} not found".format(args.doc_file))
            sys.exit(1)
        doc_contents = load_file(doc_file=args.doc_file)
    if args.delete_doc:
        try:
            polarion_doc = Document(project_id=args.project, doc_with_space="{}/{}".format(args.space, args.document))
            polarion_doc.delete()
        except Exception as e:
            log.info("Cannot get document {}/{}:{}".format(args.space, args.document,e))
    if not doc_contents:
        sys.exit(1)
    if args.upload_doc:
        if not args.project or not args.document or not args.space:
            log.info('args --project, --document, --space are required to upload doc')
            sys.exit(1)
    #verify_doc(casedoc=doc_contents)
    for item in doc_contents:
        if args.upload_doc:
            polarion_case = PolarionCase(casedoc=item, project=args.project, prefix=args.prefix, document=args.document, space=args.space, parent_id=args.parent_id, force=args.is_force)
            polarion_case.update_case()
        if args.verify_doc:
            verify_doc(casedoc=item)
    
if __name__ == "__main__":
    main()