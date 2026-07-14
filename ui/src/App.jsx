import { useEffect, useMemo, useState } from 'react';
import { API_BASE_URL, apiGet, apiPost } from './api.js';
import { metricDictionary, scoreDictionary } from './metricDictionary.js';

const DEFAULT_DATASET = 'public-baseline';

const METRIC_OPTIONS = Object.entries(metricDictionary).map(([value, details]) => ({
  value,
  label: details.label || value,
  group: details.group || 'Other metrics',
}));

const DEFAULT_COMPARE_METRICS = ['num_symbols', 'imported_function_count', 'num_sections'];
const DEFAULT_COMPARE_LIBRARIES = ['libsqlite3.0.dylib', 'libresolv.dylib'];

function buildMetricQuery(selectedMetrics) {
  return selectedMetrics.length ? selectedMetrics.join(',') : undefined;
}

function optionValue(item) {
  return item.display_name || item.canonical_name || item.value || item.library || '';
}

function buildLibraryOptions(libraries) {
  return [...libraries]
    .map((item) => {
      const value = optionValue(item);
      return { value, label: value, group: 'Libraries' };
    })
    .filter((item) => item.value)
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
}

function buildObservationVersionChoices(observations) {
  const seen = new Set();
  return observations
    .map((item) => {
      const value = item.ios_version || item.version_label || item.ios_release;
      const release = item.ios_release || 'unknown release';
      const label = item.ios_version ? `${release} - ${item.ios_version}` : String(value || '');
      return { value, label, release, group: 'Available versions' };
    })
    .filter((item) => {
      if (!item.value || seen.has(item.value)) return false;
      seen.add(item.value);
      return true;
    })
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
}

function buildVersionChoices(versions) {
  const seen = new Set();
  return versions
    .map((item) => ({
      value: item.ios_release || item.version_label,
      label: item.ios_release ? `${item.ios_release} - ${item.version_label}` : item.version_label,
      group: 'iOS versions',
    }))
    .filter((item) => {
      if (!item.value || seen.has(item.value)) return false;
      seen.add(item.value);
      return true;
    })
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
}

function groupOptions(options) {
  return options.reduce((acc, option) => {
    acc[option.group || 'Options'] = acc[option.group || 'Options'] || [];
    acc[option.group || 'Options'].push(option);
    return acc;
  }, {});
}

function selectedPreview(options, selected) {
  const labelByValue = new Map(options.map((option) => [option.value, option.label]));
  const labels = selected.map((value) => labelByValue.get(value) || value);
  if (!labels.length) return '';
  if (labels.length <= 2) return labels.join(', ');
  return `${labels.slice(0, 2).join(', ')} +${labels.length - 2} more`;
}

function MultiSelectDropdown({
  label,
  options,
  selected,
  onChange,
  emptySummary = 'No filter selected',
  selectedNoun = 'items',
  selectedPluralNoun,
  clearLabel = 'Clear selection',
  searchable = false,
  disabled = false,
}) {
  const [search, setSearch] = useState('');
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const filteredOptions = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return options;
    return options.filter((option) => `${option.label} ${option.value}`.toLowerCase().includes(needle));
  }, [options, search]);
  const grouped = useMemo(() => groupOptions(filteredOptions), [filteredOptions]);

  function toggleValue(value) {
    if (selectedSet.has(value)) {
      onChange(selected.filter((item) => item !== value));
    } else {
      onChange([...selected, value]);
    }
  }

  const nounLabel = selected.length === 1 ? selectedNoun : (selectedPluralNoun || `${selectedNoun}s`);
  const summaryLabel = selected.length
    ? `${selected.length} ${nounLabel} selected`
    : emptySummary;
  const preview = selectedPreview(options, selected);

  return (
    <div className="metricSelector">
      <label className="metricDropdownLabel">
        {label}
        <details className="metricDropdown">
          <summary aria-disabled={disabled} className={disabled ? 'disabledSummary' : ''}>
            <span>{summaryLabel}</span>
            <span className="metricDropdownHint">{disabled ? 'No options' : 'Click to select'}</span>
          </summary>
          {!disabled ? (
            <div className="metricDropdownPanel">
              <div className="metricDropdownToolbar">
                <span>{preview || 'No selection.'}</span>
                <button type="button" className="smallButton" onClick={() => onChange([])}>
                  {clearLabel}
                </button>
              </div>
              {searchable ? (
                <input
                  className="dropdownSearch"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search..."
                />
              ) : null}
              {Object.entries(grouped).map(([group, groupOptionsList]) => (
                <div className="metricDropdownGroup" key={group}>
                  <span className="metricGroupLabel">{group}</span>
                  <div className="metricDropdownList">
                    {groupOptionsList.map((option) => (
                      <label className="metricDropdownItem" key={option.value}>
                        <input
                          type="checkbox"
                          checked={selectedSet.has(option.value)}
                          onChange={() => toggleValue(option.value)}
                        />
                        <span>{option.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
              {!filteredOptions.length ? <p className="muted">No matching options.</p> : null}
            </div>
          ) : null}
        </details>
      </label>
    </div>
  );
}

function MetricSelector({ selected, onChange }) {
  return (
    <MultiSelectDropdown
      label="Exact metrics"
      options={METRIC_OPTIONS}
      selected={selected}
      onChange={onChange}
      emptySummary="All metrics"
      selectedNoun="metric"
      clearLabel="All metrics"
      searchable
    />
  );
}

function formatScalarValue(value) {
  if (value === null || value === undefined || value === '') {
    return '—';
  }
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3);
  }
  return String(value);
}

function MetricValue({ value }) {
  if (!Array.isArray(value)) {
    return <span>{formatScalarValue(value)}</span>;
  }

  if (!value.length) {
    return <span>Empty list</span>;
  }

  return (
    <details className="metricValueDetails">
      <summary>{value.length.toLocaleString()} items · click to expand</summary>
      <ul className="arrayList">
        {value.map((item, index) => (
          <li key={`${item}-${index}`}><code>{item}</code></li>
        ))}
      </ul>
    </details>
  );
}

function Card({ title, children, actions }) {
  return (
    <section className="card">
      <div className="cardHeader">
        <h2>{title}</h2>
        {actions ? <div className="cardActions">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

function StatusPill({ value }) {
  const normalized = String(value || '').toLowerCase();
  const tone = normalized.includes('high') || normalized.includes('expanded') ? 'danger' : normalized.includes('medium') ? 'warning' : 'neutral';
  return <span className={`pill ${tone}`}>{value || 'unknown'}</span>;
}

function LoadingButton({ loading, children, ...props }) {
  return (
    <button type="button" disabled={loading || props.disabled} {...props}>
      {loading ? 'Loading…' : children}
    </button>
  );
}

function ErrorBox({ error }) {
  if (!error) return null;
  return <div className="errorBox">{error}</div>;
}

function Overview({ health, versionCount, libraryCount }) {
  return (
    <Card title="Overview">
      <div className="heroGrid">
        <div>
          <p>
            DylibScope is a static-analysis platform for iOS dynamic libraries. It exposes high-level LIEF metrics,
            low-level Ghidra metrics, comparison endpoints, and derived heuristic reports through a deployed API.
          </p>
          <p className="note">
            The score is a static-complexity indicator. It does not prove that a library or iOS version is vulnerable or safe.
          </p>
        </div>
        <div className="statsGrid">
          <div className="stat"><span>API</span><strong>{health?.status || 'unknown'}</strong></div>
          <div className="stat"><span>Libraries</span><strong>{libraryCount ?? '—'}</strong></div>
          <div className="stat"><span>iOS versions</span><strong>{versionCount ?? '—'}</strong></div>
        </div>
      </div>
    </Card>
  );
}

function primaryScorePayload(report) {
  return report?.observations?.[0]?.score || report || null;
}

function LibraryExplorer({ libraries, versions }) {
  const [library, setLibrary] = useState('libsqlite3.0.dylib');
  const [iosVersion, setIosVersion] = useState('');
  const [selectedMetrics, setSelectedMetrics] = useState([]);
  const [libraryVersionChoices, setLibraryVersionChoices] = useState([]);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [data, setData] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const libraryOptions = useMemo(() => buildLibraryOptions(libraries), [libraries]);

  useEffect(() => {
    if (!libraryOptions.length) return;
    if (!libraryOptions.some((option) => option.value === library)) {
      setLibrary(libraryOptions[0].value);
    }
  }, [libraryOptions, library]);

  useEffect(() => {
    if (!library) return undefined;
    let cancelled = false;

    async function loadLibraryVersions() {
      setVersionsLoading(true);
      try {
        const response = await apiGet(`/v1/libraries/${encodeURIComponent(library)}/timeline`, {
          dataset_name: DEFAULT_DATASET,
        });
        if (cancelled) return;
        const choices = buildObservationVersionChoices(response.timeline || []);
        setLibraryVersionChoices(choices);
        if (choices.length && !choices.some((choice) => choice.value === iosVersion)) {
          setIosVersion(choices[0].value);
        }
      } catch (_) {
        if (!cancelled) {
          setLibraryVersionChoices([]);
        }
      } finally {
        if (!cancelled) {
          setVersionsLoading(false);
        }
      }
    }

    loadLibraryVersions();
    return () => {
      cancelled = true;
    };
  }, [library]);

  async function loadLibrary() {
    setLoading(true);
    setError('');
    setData(null);
    setReport(null);
    try {
      const metricQuery = {
        dataset_name: DEFAULT_DATASET,
        ios_version: iosVersion || undefined,
        metrics: buildMetricQuery(selectedMetrics),
      };
      const reportQuery = {
        dataset_name: DEFAULT_DATASET,
        ios_version: iosVersion || undefined,
      };
      const [metricsResponse, reportResponse] = await Promise.all([
        apiGet(`/v1/libraries/${encodeURIComponent(library)}/metrics`, metricQuery),
        apiGet(`/v1/libraries/${encodeURIComponent(library)}/security-report`, reportQuery),
      ]);
      setData(metricsResponse);
      setReport(reportResponse);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const fallbackVersionChoices = useMemo(() => buildVersionChoices(versions), [versions]);
  const activeVersionChoices = libraryVersionChoices.length ? libraryVersionChoices : fallbackVersionChoices;
  const firstObservation = data?.observations?.[0];
  const metricEntries = Object.entries(firstObservation?.metrics || {});
  const scorePayload = primaryScorePayload(report);

  return (
    <Card title="Library explorer">
      <div className="libraryExplorerControls">
        <label>
          Library
          <select value={library} onChange={(event) => setLibrary(event.target.value)}>
            {libraryOptions.length ? libraryOptions.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            )) : <option value={library}>{library}</option>}
          </select>
        </label>
        <label>
          Available iOS version
          <select value={iosVersion} disabled={versionsLoading || !activeVersionChoices.length} onChange={(event) => setIosVersion(event.target.value)}>
            {activeVersionChoices.length ? activeVersionChoices.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            )) : <option value="">No versions available</option>}
          </select>
        </label>
      </div>
      <MetricSelector selected={selectedMetrics} onChange={setSelectedMetrics} />
      <LoadingButton loading={loading} disabled={!library || !iosVersion} onClick={loadLibrary}>Load library</LoadingButton>
      <ErrorBox error={error} />
      {scorePayload ? (
        <div className="reportGrid">
          <div className="scoreBox">
            <span>Score</span>
            <strong>{formatScalarValue(scorePayload.score)}</strong>
          </div>
          <div className="scoreBox">
            <span>Band</span>
            <StatusPill value={scorePayload.band} />
          </div>
          <div className="scoreBox">
            <span>Confidence</span>
            <StatusPill value={scorePayload.confidence} />
          </div>
        </div>
      ) : null}
      {scorePayload?.risk_points?.length ? (
        <div>
          <h3>Risk points</h3>
          <div className="tagRow">
            {scorePayload.risk_points.map((point) => <span className="tag" key={point}>{point}</span>)}
          </div>
        </div>
      ) : null}
      {scorePayload?.top_contributors?.length ? (
        <div>
          <h3>Top contributors</h3>
          <div className="tableWrap">
            <table>
              <thead>
                <tr><th>Metric</th><th>Raw value</th><th>Normalized</th><th>Weight</th><th>Points</th></tr>
              </thead>
              <tbody>
                {scorePayload.top_contributors.map((item) => (
                  <tr key={item.metric}>
                    <td>{item.metric}</td>
                    <td>{formatScalarValue(item.raw_value)}</td>
                    <td>{formatScalarValue(item.normalized_value)}</td>
                    <td>{formatScalarValue(item.weight)}</td>
                    <td>{formatScalarValue(item.weighted_points)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
      {metricEntries.length ? (
        <div>
          <h3>Metrics</h3>
          <div className="tableWrap">
            <table className="metricsTable">
              <colgroup>
                <col className="metricNameCol" />
                <col className="metricLevelCol" />
                <col className="metricValueCol" />
                <col className="metricMeaningCol" />
              </colgroup>
              <thead>
                <tr><th>Metric</th><th>Level</th><th>Value</th><th>Meaning</th></tr>
              </thead>
              <tbody>
                {metricEntries.map(([name, payload]) => (
                  <tr key={name}>
                    <td><code>{name}</code></td>
                    <td>{payload.level}</td>
                    <td className="metricValueCell"><MetricValue value={payload.value} /></td>
                    <td>{metricDictionary[name]?.meaning || 'No description available.'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </Card>
  );
}

function CompareLibraries({ libraries, versions }) {
  const libraryOptions = useMemo(() => buildLibraryOptions(libraries), [libraries]);
  const versionOptions = useMemo(() => buildVersionChoices(versions), [versions]);
  const [selectedLibraries, setSelectedLibraries] = useState(DEFAULT_COMPARE_LIBRARIES);
  const [iosVersion, setIosVersion] = useState('6.0');
  const [selectedMetrics, setSelectedMetrics] = useState(DEFAULT_COMPARE_METRICS);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!libraryOptions.length) return;
    const available = new Set(libraryOptions.map((option) => option.value));
    const filtered = selectedLibraries.filter((item) => available.has(item));
    if (filtered.length !== selectedLibraries.length) {
      setSelectedLibraries(filtered);
    }
  }, [libraryOptions]);

  useEffect(() => {
    if (versionOptions.length && !versionOptions.some((option) => option.value === iosVersion)) {
      setIosVersion(versionOptions[0].value);
    }
  }, [versionOptions, iosVersion]);

  async function compare() {
    setLoading(true);
    setError('');
    setData(null);
    try {
      const response = await apiPost('/v1/libraries/compare', {
        libraries: selectedLibraries,
        dataset_name: DEFAULT_DATASET,
        ios_version: iosVersion,
        metrics: selectedMetrics.length ? selectedMetrics : undefined,
      });
      setData(response);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Compare libraries">
      <div className="formGrid two">
        <label>
          iOS version
          <select value={iosVersion} onChange={(event) => setIosVersion(event.target.value)}>
            {versionOptions.length ? versionOptions.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            )) : <option value={iosVersion}>{iosVersion}</option>}
          </select>
        </label>
      </div>
      <MultiSelectDropdown
        label="Libraries"
        options={libraryOptions}
        selected={selectedLibraries}
        onChange={setSelectedLibraries}
        emptySummary="No libraries selected"
        selectedNoun="library"
        selectedPluralNoun="libraries"
        clearLabel="Clear libraries"
        searchable
      />
      <MetricSelector selected={selectedMetrics} onChange={setSelectedMetrics} />
      <LoadingButton loading={loading} disabled={selectedLibraries.length < 2 || !iosVersion} onClick={compare}>Compare libraries</LoadingButton>
      {selectedLibraries.length < 2 ? <p className="muted">Select at least two libraries.</p> : null}
      <ErrorBox error={error} />
      {data ? <ComparisonResults data={data} /> : null}
    </Card>
  );
}

function CompareVersions({ libraries }) {
  const libraryOptions = useMemo(() => buildLibraryOptions(libraries), [libraries]);
  const [library, setLibrary] = useState('libsqlite3.0.dylib');
  const [versionOptions, setVersionOptions] = useState([]);
  const [selectedVersions, setSelectedVersions] = useState([]);
  const [selectedMetrics, setSelectedMetrics] = useState(DEFAULT_COMPARE_METRICS);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!libraryOptions.length) return;
    if (!libraryOptions.some((option) => option.value === library)) {
      setLibrary(libraryOptions[0].value);
    }
  }, [libraryOptions, library]);

  useEffect(() => {
    if (!library) return undefined;
    let cancelled = false;

    async function loadLibraryVersions() {
      setVersionsLoading(true);
      try {
        const response = await apiGet(`/v1/libraries/${encodeURIComponent(library)}/timeline`, {
          dataset_name: DEFAULT_DATASET,
        });
        if (cancelled) return;
        const choices = buildObservationVersionChoices(response.timeline || []);
        setVersionOptions(choices);
        const available = new Set(choices.map((choice) => choice.value));
        const retained = selectedVersions.filter((version) => available.has(version));
        if (retained.length >= 2) {
          setSelectedVersions(retained);
        } else {
          setSelectedVersions(choices.slice(0, 2).map((choice) => choice.value));
        }
      } catch (_) {
        if (!cancelled) {
          setVersionOptions([]);
          setSelectedVersions([]);
        }
      } finally {
        if (!cancelled) {
          setVersionsLoading(false);
        }
      }
    }

    loadLibraryVersions();
    return () => {
      cancelled = true;
    };
  }, [library]);

  async function compare() {
    setLoading(true);
    setError('');
    setData(null);
    try {
      const response = await apiPost(`/v1/libraries/${encodeURIComponent(library)}/compare-versions`, {
        dataset_name: DEFAULT_DATASET,
        ios_versions: selectedVersions,
        metrics: selectedMetrics.length ? selectedMetrics : undefined,
      });
      setData(response);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Compare one library across iOS versions">
      <div className="formGrid two">
        <label>
          Library
          <select value={library} onChange={(event) => setLibrary(event.target.value)}>
            {libraryOptions.length ? libraryOptions.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            )) : <option value={library}>{library}</option>}
          </select>
        </label>
      </div>
      <MultiSelectDropdown
        label="iOS versions"
        options={versionOptions}
        selected={selectedVersions}
        onChange={setSelectedVersions}
        emptySummary={versionsLoading ? 'Loading versions' : 'No versions selected'}
        selectedNoun="version"
        clearLabel="Clear versions"
        searchable
        disabled={versionsLoading || !versionOptions.length}
      />
      <MetricSelector selected={selectedMetrics} onChange={setSelectedMetrics} />
      <LoadingButton loading={loading} disabled={!library || selectedVersions.length < 2} onClick={compare}>Compare versions</LoadingButton>
      {selectedVersions.length < 2 ? <p className="muted">Select at least two versions for this library.</p> : null}
      <ErrorBox error={error} />
      {data ? <ComparisonResults data={data} showDelta /> : null}
    </Card>
  );
}

function VersionSummary({ versions }) {
  const versionOptions = useMemo(() => buildVersionChoices(versions), [versions]);
  const [iosVersion, setIosVersion] = useState('10.3.3');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!versionOptions.length) return;
    if (!versionOptions.some((option) => option.value === iosVersion)) {
      setIosVersion(versionOptions[0].value);
    }
  }, [versionOptions, iosVersion]);

  async function loadSummary() {
    setLoading(true);
    setError('');
    setData(null);
    try {
      const response = await apiGet(`/v1/ios-versions/${encodeURIComponent(iosVersion)}/security-summary`, {
        dataset_name: DEFAULT_DATASET,
        limit: 10,
      });
      setData(response);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="iOS version summary">
      <div className="formGrid compact">
        <label>
          iOS version
          <select value={iosVersion} onChange={(event) => setIosVersion(event.target.value)}>
            {versionOptions.length ? versionOptions.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            )) : <option value={iosVersion}>{iosVersion}</option>}
          </select>
        </label>
      </div>
      <LoadingButton loading={loading} disabled={!iosVersion} onClick={loadSummary}>Load summary</LoadingButton>
      <ErrorBox error={error} />
      {data ? (
        <div>
          <div className="reportGrid">
            <div className="scoreBox"><span>Observations</span><strong>{data.observation_count}</strong></div>
            <div className="scoreBox"><span>Average score</span><strong>{formatScalarValue(data.score_statistics?.average_score)}</strong></div>
            <div className="scoreBox"><span>Median score</span><strong>{formatScalarValue(data.score_statistics?.median_score)}</strong></div>
          </div>
          <h3>Band counts</h3>
          <div className="tagRow">
            {Object.entries(data.band_counts || {}).map(([key, value]) => <span className="tag" key={key}>{key}: {value}</span>)}
          </div>
          <h3>Top libraries</h3>
          <div className="tableWrap">
            <table>
              <thead><tr><th>Library</th><th>Score</th><th>Band</th><th>Confidence</th><th>Risk points</th></tr></thead>
              <tbody>
                {(data.top_libraries || []).map((item) => (
                  <tr key={`${item.library}-${item.ios_version}`}>
                    <td>{item.library}</td>
                    <td>{formatScalarValue(item.score)}</td>
                    <td><StatusPill value={item.band} /></td>
                    <td>{item.confidence}</td>
                    <td>{(item.risk_points || []).join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </Card>
  );
}

function ComparisonResults({ data, showDelta = false }) {
  return (
    <div className="resultsBlock">
      <p className="note">{data.summary}</p>
      {data.resolved_observations?.length ? (
        <details>
          <summary>Resolved observations</summary>
          <pre>{JSON.stringify(data.resolved_observations, null, 2)}</pre>
        </details>
      ) : null}
      <div className="tableWrap">
        <table>
          <thead>
            <tr>
              <th>Metric</th>
              <th>Level</th>
              <th>Values</th>
              <th>Leader</th>
              {showDelta ? <><th>Delta</th><th>Direction</th></> : <><th>Difference</th><th>Ratio</th></>}
            </tr>
          </thead>
          <tbody>
            {(data.results || []).map((row) => (
              <tr key={row.metric}>
                <td>{row.metric}</td>
                <td>{row.level || '—'}</td>
                <td><pre className="inlinePre">{JSON.stringify(row.values, null, 2)}</pre></td>
                <td>{row.leader || '—'}</td>
                {showDelta ? (
                  <>
                    <td>{formatScalarValue(row.absolute_delta)} ({formatScalarValue(row.percent_change)}%)</td>
                    <td>{row.direction}</td>
                  </>
                ) : (
                  <>
                    <td>{formatScalarValue(row.absolute_difference)}</td>
                    <td>{formatScalarValue(row.ratio_high_to_low)}</td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MetricReference() {
  const grouped = useMemo(() => {
    return Object.entries(metricDictionary).reduce((acc, [name, details]) => {
      acc[details.group] = acc[details.group] || [];
      acc[details.group].push([name, details]);
      return acc;
    }, {});
  }, []);

  return (
    <Card title="Metric and score reference">
      <p className="note">This section explains what the UI values mean and how to read them.</p>
      <div className="referenceGrid">
        {Object.entries(scoreDictionary).map(([key, value]) => (
          <div className="referenceItem" key={key}>
            <h3>{key}</h3>
            <p>{value}</p>
          </div>
        ))}
      </div>
      {Object.entries(grouped).map(([group, entries]) => (
        <div key={group}>
          <h3>{group}</h3>
          <div className="referenceGrid">
            {entries.map(([name, details]) => (
              <div className="referenceItem" key={name}>
                <h4>{details.label}</h4>
                <code>{name}</code>
                <p>{details.meaning}</p>
                <p className="muted">{details.interpretation}</p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </Card>
  );
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [libraries, setLibraries] = useState([]);
  const [versions, setVersions] = useState([]);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    async function bootstrap() {
      try {
        const [healthResponse, librariesResponse, versionsResponse] = await Promise.all([
          apiGet('/health'),
          apiGet('/v1/libraries', { dataset_name: DEFAULT_DATASET }),
          apiGet('/v1/ios-versions'),
        ]);
        setHealth(healthResponse);
        setLibraries(librariesResponse.libraries || []);
        setVersions(versionsResponse.ios_versions || []);
      } catch (err) {
        setLoadError(err.message);
      }
    }
    bootstrap();
  }, []);

  return (
    <main>
      <header className="topBar">
        <div>
          <h1>DylibScope</h1>
          <p>Static security trend analysis of iOS dynamic libraries</p>
        </div>
        <a href={`${API_BASE_URL}/docs`} target="_blank" rel="noreferrer">API docs</a>
      </header>
      <ErrorBox error={loadError} />
      <Overview health={health} libraryCount={libraries.length} versionCount={versions.length} />
      <LibraryExplorer libraries={libraries} versions={versions} />
      <CompareLibraries libraries={libraries} versions={versions} />
      <CompareVersions libraries={libraries} />
      <VersionSummary versions={versions} />
      <MetricReference />
    </main>
  );
}
