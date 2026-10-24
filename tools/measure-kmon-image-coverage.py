"""Measure published image comparisons and repeatability on a fixed process cohort.

Counts are observed addresses, not continuous mapping identity or host-wide coverage.
Pass four runs (baseline A/B, candidate A/B) with --fixed-cohort for paired comparisons.
"""
import argparse,collections,json,pathlib,re

def require(condition,message):
 if not condition:raise ValueError(message)

def load(path): return json.loads(pathlib.Path(path).read_text(encoding='utf-8-sig'))
def merge(ranges):
 out=[]
 for start,end in sorted(ranges):
  require(0<=start<end<=2**64,'invalid comparison range')
  if out and start<=out[-1][1]:out[-1][1]=max(out[-1][1],end)
  else:out.append([start,end])
 return out
def size(ranges):return sum(b-a for a,b in ranges)
def measure(root):
 root=pathlib.Path(root);v=load(root/'validation.json')
 watched={x['pid'] for x in load(root/'fixtures.json')}|{x['pid'] for x in load(root/'observed-processes.json')}
 # Descendants (notably the fixtures' conhosts) inherit the native watch.
 # Use the union of recorded watch snapshots; fixture families stay alive
 # through final drain in this harness. This is not a general PID-reuse ledger.
 console=(root/'console.stdout.log').read_text(encoding='utf-8-sig',errors='replace')
 for row in console.splitlines():
  if row.lstrip().startswith('watch:'):watched.update(map(int,re.findall(r'\bpid=(\d+)',row)))
 processes={};complete=collections.defaultdict(set);traversed=collections.defaultdict(set);progress={};reasons=collections.Counter();ranges_short=0
 for file in sorted(root.glob('kmon-events.*.jsonl')):
  with file.open(encoding='utf-8-sig') as source:
   for line in source:
    e=json.loads(line);k=e['kind'];ev=e.get('evidence',{})
    if k not in ['coverage.layout','coverage.region','coverage.image','coverage.image_progress']:continue
    pid=e['pid'];creation=int(ev.get('process_create_time','0'));boot=ev.get('boot_id','')
    group='watched' if pid in watched else ('kernel' if pid<=4 else 'background')
    key=f'{boot}:{pid}:{creation}'
    # Cohort membership comes from identified observations, including layouts
    # with zero compared bytes. Intersecting only positive comparison results
    # would hide an entire process whose coverage regressed to zero.
    identified=pid>4 and creation>0 and boot not in ('','unknown')
    if identified:
     processes.setdefault(key,{'pid':pid,'creation':creation,'boot':boot,'group':group,'ranges':[]})
    if k=='coverage.region' and ev.get('source')=='executable_page_compare':
     if pid>4 and not identified:raise ValueError('Unidentified image comparison')
     intervals=[]
     for item in ev.get('compared_ranges','').split(','):
      if item:
       a,n=map(int,item.split(':'));intervals.append([a,a+n])
     represented=size(intervals);declared=int(ev.get('compared_bytes',0));require(represented<=declared,'range accounting mismatch')
     ranges_short+=declared-represented
     if intervals:
      p=processes.setdefault(key,{'pid':pid,'creation':creation,'boot':boot,'group':group,'ranges':[]})
      p['ranges'].extend(intervals)
    image=key+':'+ev.get('image_base','0')
    if k=='coverage.image' and e['summary'] in ['cycle_complete','cycle_complete_with_gaps']:
     traversed[group].add(image)
     if int(ev['requested_bytes'])>0 and int(ev['compared_bytes'])==int(ev['requested_bytes']) and all(int(ev[x])==0 for x in ['failed_bytes','skipped_bytes','remaining_pages']):complete[group].add(image)
    if k=='coverage.image_progress':
     progress[image]={'group':group,'image':e['image'],'remaining_pages':int(ev.get('remaining_pages',0)),'compared_bytes':int(ev.get('compared_bytes',0)),'loaded':ev.get('reference_loaded')=='true','completed_cycles':int(ev.get('completed_cycles',0))}
     reasons[ev.get('coverage_reason','')]+=1
 for p in processes.values():p['ranges']=merge(p['ranges']);p['unique_bytes']=size(p['ranges'])
 require(ranges_short==0,'published comparison ranges omit bytes; exact range comparison is unavailable')
 groups={}
 for group in ['watched','background','kernel']:
  own=[p for p in processes.values() if p['group']==group]
  groups[group]={'observed_identified_process_generations':len(own),'processes_with_compared_bytes':sum(p['unique_bytes']>0 for p in own),'unique_observed_address_bytes':sum(p['unique_bytes'] for p in own),'traversed_image_instances':len(traversed[group]),'fully_compared_image_instances':len(complete[group]),'final_cache_unfinished_images':sum(x['group']==group and x['remaining_pages']>0 for x in progress.values())}
 report={'binary':v['binary_sha256'],'observe_seconds':v['observe_seconds'],'passed':v['passed'],'watched_pids':sorted(watched),'groups':groups,'completed_images':{g:sorted(s) for g,s in complete.items()},'compared_bytes_omitted_from_ranges':ranges_short,'processes':processes,'final_progress_reasons':dict(reasons),'pipeline':v['final_pipeline'],'claim':'Deduplicated published process-generation/address bytes, not continuous mapping attestation; completion counts exclude cache history.'}
 (root/'image-coverage.json').write_text(json.dumps(report,indent=2))
 print(json.dumps({'run':str(root),'groups':groups,'omitted':ranges_short}))
 return report

def cohort(reports):
 return set.intersection(*[{key for key,p in r['processes'].items() if p['group']=='background'} for r in reports])

def compare(a,b,common=None):
 if common is None:common=cohort([a,b])
 require(common<=cohort([a,b]),'cohort includes unidentified or watched process generations')
 aa=bb=both=0
 for key in common:
  x,y=a['processes'][key]['ranges'],b['processes'][key]['ranges']
  sx,sy=size(x),size(y);aa+=sx;bb+=sy;both+=sx+sy-size(merge(x+y))
 ca={key for key in a['completed_images'].get('background',[]) if key.rsplit(':',1)[0] in common}
 cb={key for key in b['completed_images'].get('background',[]) if key.rsplit(':',1)[0] in common}
 union=aa+bb-both
 return {'cohort_policy':'identified background observations, including zero-byte coverage','common_background_process_generations':len(common),'baseline_zero_compared_processes':sum(not a['processes'][k]['ranges'] for k in common),'candidate_zero_compared_processes':sum(not b['processes'][k]['ranges'] for k in common),'baseline_unique_bytes':aa,'candidate_unique_bytes':bb,'newly_compared_address_bytes':bb-both,'baseline_only_address_bytes':aa-both,'shared_address_bytes':both,'union_address_bytes':union,'symmetric_difference_bytes':aa+bb-2*both,'jaccard':both/union if union else None,'baseline_fully_compared_image_instances':len(ca),'candidate_fully_compared_image_instances':len(cb),'newly_fully_compared_image_instances':len(cb-ca),'baseline_only_fully_compared_image_instances':len(ca-cb)}

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('runs',nargs='+')
 parser.add_argument('--fixed-cohort',action='store_true')
 parser.add_argument('--cached',action='store_true',help='reuse previously measured image-coverage.json files')
 parser.add_argument('--output',type=pathlib.Path,help='comparison report path; defaults to the last run directory')
 args=parser.parse_args()
 reports=[load(pathlib.Path(path)/'image-coverage.json') if args.cached else measure(path) for path in args.runs]
 for report in reports:require(report['compared_bytes_omitted_from_ranges']==0,'incomplete cached range evidence')
 if len(reports)>1:
  common=cohort(reports) if args.fixed_cohort else None
  comparisons=[dict(run=path,**compare(reports[0],r,common)) for path,r in zip(args.runs[1:],reports[1:])]
  paired=[dict(runs=args.runs[i:i+2],**compare(reports[i],reports[i+1],common)) for i in range(0,len(reports)-1,2)]
  report=dict(fixed_cohort=args.fixed_cohort,comparisons=comparisons,repeatability_pairs=paired)
  destination=args.output or pathlib.Path(args.runs[-1]).joinpath('coverage-comparison.json')
  destination.write_text(json.dumps(report,indent=2))
  print(json.dumps(report,indent=2))
