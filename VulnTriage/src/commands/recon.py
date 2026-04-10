import logging
import os
import dataclasses
from recon.detect_lang import detect_language
from recon.tech_stack_matcher import TechStackMatcher
from recon.matcher_py import PythonMatcher
from recon.matcher_java import JavaMatcher


def run(args):
    logging.info("recon_start repo=%s lang=%s", args.repo, args.lang)
    
    # Get patterns directory
    patterns_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'patterns')
    patterns_dir = os.path.abspath(patterns_dir)
    
    # Step 1: Detect language
    lang = detect_language(args.repo, args.lang)
    logging.info("detected_language=%s", lang)
    
    # Step 2: Match technology stack (based on tech_stack.yaml patterns)
    tech_stack_matcher = TechStackMatcher(patterns_dir)
    tech_stack = tech_stack_matcher.match_tech_stack(args.repo)
    matched_frameworks = tech_stack_matcher.get_matched_frameworks(args.repo)
    logging.info("tech_stack_matched items=%d frameworks=%s", len(tech_stack), matched_frameworks)
    
    # Step 3: Select appropriate matcher based on language and perform pattern-based matching
    if lang == 'py':
        matcher = PythonMatcher(patterns_dir)
        result = matcher.scan_repo(args.repo)
    elif lang == 'java':
        matcher = JavaMatcher(patterns_dir)
        result = matcher.scan_repo(args.repo)
    else:
        logging.warning("Unsupported language: %s", lang)
        return {
            "language": lang,
            "repo": args.repo,
            "tech_stack": [dataclasses.asdict(ts) for ts in tech_stack],
            "entrypoints": [],
            "sanitizers": [],
            "sinks": [],
            "exports": [],
            "deps": []
        }
    
    # Convert dataclasses to dicts
    inventory = {
        "language": lang,
        "repo": args.repo,
        "tech_stack": [dataclasses.asdict(ts) for ts in tech_stack],
        "entrypoints": [dataclasses.asdict(ep) for ep in result['entrypoints']],
        "sanitizers": [dataclasses.asdict(s) for s in result['sanitizers']],
        "sinks": [dataclasses.asdict(s) for s in result['sinks']],
        "exports": [dataclasses.asdict(e) for e in result['exports']],
        "deps": [dataclasses.asdict(d) for d in result['deps']]
    }
    
    logging.info("recon_done tech_stack=%d entrypoints=%d sanitizers=%d sinks=%d exports=%d deps=%d", 
                 len(inventory["tech_stack"]),
                 len(inventory["entrypoints"]), len(inventory["sanitizers"]), 
                 len(inventory["sinks"]), len(inventory["exports"]), len(inventory["deps"]))
    return inventory
