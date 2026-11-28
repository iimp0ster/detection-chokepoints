// Select the same rows used in the reviewed prototype from the approved Explorer dataset.
export function projectStudy(dataset, selection) {
  const study = dataset.studies.find(item=>item.id===selection.study && item.revision===selection.revision);
  if (dataset.schema!=="detection-lens-explorer/v1" || study?.evidenceClass!=="Measured") {
    throw new Error("The selected measured study is unavailable.");
  }
  const points=study.groups.filter(point=>point.profile===selection.profile && point.arm===selection.arm);
  if (!points.some(point=>point.cutoff===null) || !Object.hasOwn(study.cohorts,selection.cohort)) {
    throw new Error("The selected replay cohort is unavailable.");
  }
  points.sort((a,b)=>(a.cutoff??Infinity)-(b.cutoff??Infinity));
  return {
    lenses:[...study.lenses],
    metrics:selection.metrics,
    points:points.map(point=>({
      cutoffMs:point.cutoff,
      rows:Object.fromEntries(Object.entries(point.rows).map(([key,[cohorts]])=>[key,
        Object.fromEntries(Object.keys(selection.metrics).map(metric=>[metric,cohorts[selection.cohort][metric]]))
      ])),
      approvedMinimum:Object.fromEntries(Object.keys(selection.metrics).map(metric=>[
        metric,point.minimum[selection.cohort][metric]
      ]))
    }))
  };
}

