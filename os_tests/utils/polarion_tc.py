#!/usr/bin/env python3
"""
This module exports test cases from Polarion documents

Export test cases of documents in a space to json or text file like below:
  {
    "work_item_id": "VIRT-296346",
    "title": "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_cfg_no_wheel",
    "documents": [
      "OS-TESTS TestCloudInit Test Cases"
    ]
  }

Usage examples:
# Export test cases of all documents in a space to tc.json (overwrite)
python polarion_tc.py --project RHELVIRT --space "OS-Tests" --out polarion_tc.json --json

# Export test cases of a single document and append/merge into existing tc.json
python polarion_tc.py --project RHELVIRT --space "OS-Tests" --document "OS-TESTS TestCloudInit Test Cases" --out polarion_tc.json --json --append

# Print to stdout (text)
python polarion_tc.py --project RHELVIRT --space "OS-Tests"
"""
import argparse
import json
import os
import sys
from typing import List, Dict, Any
from pylero.document import Document
from pylero.work_item import TestCase

class PolarionTCManager:
    def __init__(self, project: str, space: str, out: str = None, as_json: bool = True, append: bool = False, verbose: bool = False):
        self.project = project
        self.space = space
        self.out = out
        self.as_json = as_json
        self.append = append
        self.verbose = verbose

    def _log(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def list_documents_in_space(self) -> List[Any]:
        """
        Return a list of document descriptors in the given space.
        Uses Document.get_documents with compatible parameter names.
        """
        self._log(f"Listing documents in space '{self.space}' (project {self.project}) ...")
        docs = None
        # Try common signatures
        try:
            docs = Document.get_documents(proj=self.project, space=self.space)
        except TypeError:
            try:
                docs = Document.get_documents(project_id=self.project, space=self.space)
            except Exception as e:
                raise RuntimeError(f"Failed to list documents for space '{self.space}': {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to list documents for space '{self.space}': {e}")
        if docs is None:
            return []
        return list(docs)

    def _doc_title_from_descriptor(self, doc_desc: Any) -> str:
        """
        Try to extract a human-readable document title from doc descriptor object/dict.
        """
        # if it's a dict-like
        if isinstance(doc_desc, dict):
            for k in ("title", "name", "id"):
                if k in doc_desc and doc_desc[k]:
                    return str(doc_desc[k])
            # fallback to str
            return str(doc_desc)
        # if it's an object with attributes
        for attr in ("title", "name", "id"):
            if hasattr(doc_desc, attr):
                val = getattr(doc_desc, attr)
                if val:
                    return str(val)
        # fallback
        return str(doc_desc)

    def extract_testcases_from_document(self, doc_title: str) -> List[Dict[str, Any]]:
        """
        Extract testcases from a single document (doc_title is just the title string).
        Returns list of dicts: {"work_item_id": ..., "title": ..., "documents": [doc_title]}
        """
        doc_with_space = f"{self.space}/{doc_title}"
        self._log(f"Processing document: {doc_with_space}")
        try:
            doc = Document(project_id=self.project, doc_with_space=doc_with_space)
        except Exception as e:
            # If direct instantiation fails, try alternative param names or fail gracefully
            try:
                doc = Document(proj=self.project, doc_with_space=doc_with_space)
            except Exception as e2:
                self._log(f"  [WARN] Cannot instantiate Document('{doc_with_space}'): {e2}")
                return []

        tc_list = []
        try:
            # query work items for this document
            items = doc.get_work_items(None, True, ["work_item_id", "title", "type"])
        except Exception as e:
            self._log(f"  [WARN] get_work_items failed for {doc_with_space}: {e}")
            return []

        for tc in items:
            # ensure it's a testcase
            try:
                tc_type = getattr(tc, "type", None) or tc.__dict__.get("type") if hasattr(tc, "__dict__") else None
            except Exception:
                tc_type = None
            # fallback: if 'type' not available, treat as testcase if work_item_id and title exist
            if tc_type and str(tc_type).lower() != "testcase":
                continue

            try:
                wid = getattr(tc, "work_item_id", None) or tc.__dict__.get("work_item_id") if hasattr(tc, "__dict__") else None
                title = getattr(tc, "title", None) or tc.__dict__.get("title") if hasattr(tc, "__dict__") else None
            except Exception:
                wid = None
                title = None

            # some pylero versions might return strings or simple objects; ensure conversion
            if not wid:
                # try attribute name 'id' or 'uri' or fallback to str(tc)
                wid = getattr(tc, "id", None) or getattr(tc, "workItemId", None) or None
            if not title:
                # fallback
                title = str(tc)

            if not wid or not title:
                # skip malformed entries
                continue

            tc_list.append({"work_item_id": str(wid), "title": str(title), "documents": [doc_title]})

        self._log(f"  Found {len(tc_list)} testcases in document '{doc_title}'")
        return tc_list

    @staticmethod
    def _load_existing(filepath: str) -> List[Dict[str, Any]]:
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                else:
                    # not a list -> try to coerce
                    return list(data)
        except Exception:
            # could be a text file; return []
            return []

    @staticmethod
    def _map_by_wid(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        d = {}
        for r in records:
            wid = r.get("work_item_id")
            if not wid:
                continue
            if wid not in d:
                # make a copy
                d[wid] = dict(r)
                # normalize documents field
                docs = d[wid].get("documents", [])
                if not isinstance(docs, list):
                    d[wid]["documents"] = [docs]
            else:
                # merge documents lists if duplicate wid in input
                existing_docs = d[wid].get("documents", [])
                new_docs = r.get("documents", [])
                if isinstance(new_docs, list):
                    for nd in new_docs:
                        if nd not in existing_docs:
                            existing_docs.append(nd)
                    d[wid]["documents"] = existing_docs
        return d

    def merge_records(self, base: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge incoming list into base list using work_item_id as key.
        If work_item_id exists: update title to incoming's title and extend documents list.
        Otherwise append incoming record.
        Returns merged list.
        """
        base_map = self._map_by_wid(base)
        inc_map = self._map_by_wid(incoming)

        # merge: incoming overrides title and extends documents
        for wid, rec in inc_map.items():
            if wid in base_map:
                # update title if different
                if rec.get("title") and rec.get("title") != base_map[wid].get("title"):
                    base_map[wid]["title"] = rec.get("title")
                # merge documents list
                base_docs = base_map[wid].get("documents", [])
                for d in rec.get("documents", []):
                    if d not in base_docs:
                        base_docs.append(d)
                base_map[wid]["documents"] = base_docs
            else:
                base_map[wid] = rec

        # return list
        return list(base_map.values())

    def run(self, document: str = None):
        """
        Main entry.
        If document is None -> process all documents in space.
        Otherwise -> process only the given document.
        """
        results_accum: List[Dict[str, Any]] = []

        if document:
            docs_to_process = [document]
        else:
            # list all docs in space
            doc_descriptors = self.list_documents_in_space()
            docs_to_process = []
            for desc in doc_descriptors:
                title = self._doc_title_from_descriptor(desc)
                if title:
                    docs_to_process.append(title)

        self._log(f"Documents to process: {len(docs_to_process)}")

        for doc_title in docs_to_process:
            try:
                list_for_doc = self.extract_testcases_from_document(doc_title)
                # Merge into accumulator (note: do not merge with existing file yet; accumulate then merge at end)
                results_accum.extend(list_for_doc)
            except Exception as e:
                self._log(f"[ERROR] Failed processing document '{doc_title}': {e}")

        # Load existing if append
        existing = []
        if self.append and self.out:
            existing = self._load_existing(self.out)
            if existing:
                self._log(f"Loaded {len(existing)} existing records from {self.out}")

        # Merge existing and new results
        if existing:
            merged = self.merge_records(existing, results_accum)
        else:
            # deduplicate within results_accum (by work_item_id)
            merged = self.merge_records([], results_accum)

        # Save or print
        if self.out:
            # ensure directory exists
            outdir = os.path.dirname(os.path.abspath(self.out))
            if outdir and not os.path.exists(outdir):
                try:
                    os.makedirs(outdir, exist_ok=True)
                except Exception:
                    pass
            if self.as_json:
                with open(self.out, "w", encoding="utf-8") as f:
                    json.dump(merged, f, indent=2, ensure_ascii=False)
                self._log(f"Wrote {len(merged)} records to {self.out}")
            else:
                with open(self.out, "w", encoding="utf-8") as f:
                    for rec in merged:
                        f.write(f"{rec.get('work_item_id')}: {rec.get('title')}\n")
                self._log(f"Wrote {len(merged)} records to {self.out}")
        else:
            # print to stdout
            if self.as_json:
                print(json.dumps(merged, indent=2, ensure_ascii=False))
            else:
                for rec in merged:
                    print(f"{rec.get('work_item_id')}: {rec.get('title')}")

        return merged


def main():
    parser = argparse.ArgumentParser(description="Extract/merge test cases from Polarion Documents in a space")
    parser.add_argument("--project", required=True, help="Polarion project ID, e.g., RHELVIRT")
    parser.add_argument("--space", required=True, help="Document space, e.g., OS-Tests")
    parser.add_argument("--document", help="Document title, e.g., 'OS-TESTS TestCloudInit Test Cases' (optional)")
    parser.add_argument("--out", help="Output file to save results, e.g., tc.json (optional)")
    parser.add_argument("--json", action="store_true", help="Write output in JSON format (default if --json is set)")
    parser.add_argument("--append", action="store_true", help="Append/merge with existing output file if present")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    manager = PolarionTCManager(
        project=args.project,
        space=args.space,
        out=args.out,
        as_json=bool(args.json),
        append=bool(args.append),
        verbose=bool(args.verbose),
    )

    merged = manager.run(document=args.document)

    print(f"\nDone. Total testcases in result: {len(merged)}")


if __name__ == "__main__":
    main()
