import { useEffect, useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { API_BASE_URL, apiGet, apiPost, setApiAuthToken } from './api.js';
import { authConfigured, ensureAnonymousSession, onAuthStateChange } from './auth.js';
import { metricDictionary, scoreDictionary } from './metricDictionary.js';

const DEFAULT_DATASET = 'public-baseline';

const METRIC_OPTIONS = Object.entries(metricDictionary).map(([value, details]) => ({
  value,
  label: details.label || value,
  group: details.group || 'Other metrics',
}));

const DEFAULT_COMPARE_METRICS = ['num_symbols', 'imported_function_count', 'num_sections'];
const DEFAULT_COMPARE_LIBRARIES = ['libsqlite3.0.dylib', 'libresolv.dylib'];
const DEFAULT_TIMELINE_METRIC = 'num_symbols';
const PUBLISHED_PLOT_BASE_URL = 'https://sebastianion.github.io/dylibscope';
const PUBLISHED_PLOTS = [
  {
    title: 'High-level analysis evolution',
    description: 'Full Plotly dashboard for LIEF-derived Mach-O metadata such as symbols, imports, exports, and sections.',
    path: 'high_level_analysis_dylib_evolution.html',
  },
  {
    title: 'Low-level analysis evolution',
    description: 'Full Plotly dashboard for Ghidra-derived implementation metrics such as CFG edges, allocation calls, syscalls, and Mach-port usage.',
    path: 'low_level_analysis_dylib_evolution.html',
  },
];
const CHART_PALETTE = ['#0f172a', '#2563eb', '#16a34a', '#d97706', '#dc2626', '#7c3aed'];


function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function metricDisplayName(metricName) {
  return metricDictionary[metricName]?.label || metricName;
}

function metricInterpretation(metricName) {
  return metricDictionary[metricName]?.meaning || 'Numeric static-analysis metric.';
}

function getMetricValue(observation, metricName) {
  const metric = observation?.metrics?.[metricName];
  if (!metric) return null;
  return metric.value;
}

function versionDisplayLabel(observation) {
  const release = observation?.ios_release;
  const label = observation?.ios_version || observation?.version_label;
  if (release && label) return `${release} - ${label}`;
  return String(label || release || 'unknown');
}

function compactVersionLabel(value) {
  const label = String(value || 'unknown');
  if (label.includes(' - ')) return label.split(' - ')[0];
  const match = label.match(/(?:^|_)(\d+(?:\.\d+){1,2})(?:_|$)/);
  return match ? match[1] : label;
}

function formatCompactChartNumber(value) {
  if (!isFiniteNumber(value)) return value;
  return Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 2 }).format(value);
}

function sortTimeline(timeline) {
  return [...timeline].sort((a, b) => {
    const aRelease = Number.parseFloat(a.ios_release || '');
    const bRelease = Number.parseFloat(b.ios_release || '');
    if (Number.isFinite(aRelease) && Number.isFinite(bRelease) && aRelease !== bRelease) {
      return aRelease - bRelease;
    }
    return versionDisplayLabel(a).localeCompare(versionDisplayLabel(b), undefined, { numeric: true });
  });
}

function buildTimelineMetricOptions(timeline) {
  const names = new Set();
  timeline.forEach((observation) => {
    Object.entries(observation?.metrics || {}).forEach(([name, payload]) => {
      if (isFiniteNumber(payload?.value)) {
        names.add(name);
      }
    });
  });
  const known = METRIC_OPTIONS.filter((option) => names.has(option.value));
  const knownValues = new Set(known.map((option) => option.value));
  const unknown = [...names]
    .filter((name) => !knownValues.has(name))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
    .map((name) => ({ value: name, label: name, group: 'Other metrics' }));
  return [...known, ...unknown];
}

function chooseTimelineMetric(timeline) {
  const options = buildTimelineMetricOptions(timeline);
  if (options.some((option) => option.value === DEFAULT_TIMELINE_METRIC)) {
    return DEFAULT_TIMELINE_METRIC;
  }
  return options[0]?.value || DEFAULT_TIMELINE_METRIC;
}

function buildTimelineChartRows(timeline, metricName) {
  return sortTimeline(timeline)
    .map((observation) => {
      const fullVersion = versionDisplayLabel(observation);
      return {
        version: compactVersionLabel(fullVersion),
        fullVersion,
        value: getMetricValue(observation, metricName),
      };
    })
    .filter((row) => isFiniteNumber(row.value));
}

function buildComparisonChartData(data) {
  const numericResults = (data?.results || [])
    .filter((row) => Object.values(row.values || {}).some((value) => isFiniteNumber(value)))
    .slice(0, 5);
  const labels = [];
  numericResults.forEach((row) => {
    Object.keys(row.values || {}).forEach((label) => {
      if (!labels.includes(label)) labels.push(label);
    });
  });
  const rows = labels.map((label) => {
    const chartRow = {
      version: compactVersionLabel(label),
      fullVersion: label,
    };
    numericResults.forEach((result) => {
      const value = result.values?.[label];
      chartRow[result.metric] = isFiniteNumber(value) ? value : null;
    });
    return chartRow;
  });
  return { rows, metrics: numericResults.map((row) => row.metric) };
}

function buildLibraryComparisonChartData(data) {
  const numericResults = (data?.results || [])
    .filter((row) => Object.values(row.values || {}).some((value) => isFiniteNumber(value)))
    .slice(0, 5);
  const labels = [];
  numericResults.forEach((row) => {
    Object.keys(row.values || {}).forEach((label) => {
      if (!labels.includes(label)) labels.push(label);
    });
  });
  const rows = labels.map((label) => {
    const chartRow = { library: label };
    numericResults.forEach((result) => {
      const value = result.values?.[label];
      chartRow[result.metric] = isFiniteNumber(value) ? value : null;
    });
    return chartRow;
  });
  return { rows, metrics: numericResults.map((row) => row.metric) };
}

function buildBandChartRows(summary) {
  const counts = summary?.band_counts || {};
  const order = ['low', 'medium', 'high'];
  return [...new Set([...order, ...Object.keys(counts)])]
    .filter((band) => counts[band] !== undefined)
    .map((band) => ({ band, count: counts[band] }));
}

function buildTopScoreRows(summary) {
  return (summary?.top_libraries || [])
    .slice(0, 10)
    .map((item) => ({ library: item.library, score: item.score }))
    .filter((row) => isFiniteNumber(row.score));
}

function buildMetricQuery(selectedMetrics) {
  return selectedMetrics.length ? selectedMetrics.join(',') : undefined;
}

function datasetDisplayName(dataset) {
  return dataset?.name || DEFAULT_DATASET;
}

function datasetLabel(dataset) {
  const name = datasetDisplayName(dataset);
  const visibility = dataset?.visibility || 'public';
  const trust = dataset?.trust_level || dataset?.trust || '';
  if (name === DEFAULT_DATASET) return `${name} - public baseline`;
  return `${name} - ${visibility}${trust ? `, ${trust}` : ''}`;
}

function isUserProvidedDataset(datasetName, datasets) {
  const dataset = datasets.find((item) => item.name === datasetName);
  return dataset?.source_type === 'user_manual' || dataset?.trust_level === 'user_provided_unverified';
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


function ChartPanel({ title, description, children }) {
  return (
    <div className="chartPanel">
      <div className="chartHeader">
        <div>
          <h3>{title}</h3>
          {description ? <p className="muted">{description}</p> : null}
        </div>
      </div>
      {children}
    </div>
  );
}

function EmptyChartState({ children }) {
  return <div className="emptyChartState">{children}</div>;
}

function MetricTimelineChart({ rows, metricName, title = 'Metric evolution', description }) {
  if (!rows.length) {
    return (
      <ChartPanel title={title} description={description}>
        <EmptyChartState>No numeric timeline data is available for this metric.</EmptyChartState>
      </ChartPanel>
    );
  }

  if (rows.length < 2) {
    return (
      <ChartPanel title={title} description={description}>
        <EmptyChartState>At least two numeric observations are required to draw an evolution chart.</EmptyChartState>
      </ChartPanel>
    );
  }

  return (
    <ChartPanel title={title} description={description}>
      <div className="chartFrame">
        <ResponsiveContainer width="100%" height={280}>
          <LineChart data={rows} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="version" />
            <YAxis tickFormatter={formatCompactChartNumber} width={72} />
            <Tooltip
              formatter={(value) => [formatScalarValue(value), metricDisplayName(metricName)]}
              labelFormatter={(_, payload) => payload?.[0]?.payload?.fullVersion || 'iOS version'}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="value"
              name={metricDisplayName(metricName)}
              stroke={CHART_PALETTE[0]}
              strokeWidth={2.5}
              dot={{ r: 3 }}
              activeDot={{ r: 5 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}

function MultiMetricLineChart({ rows, metrics, title, description, xKey = 'version' }) {
  if (!rows.length || !metrics.length) {
    return (
      <ChartPanel title={title} description={description}>
        <EmptyChartState>No numeric values are available for a contextual chart.</EmptyChartState>
      </ChartPanel>
    );
  }

  return (
    <ChartPanel title={title} description={description}>
      <div className="chartFrame">
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={rows} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey={xKey} />
            <YAxis tickFormatter={formatCompactChartNumber} width={72} />
            <Tooltip
              formatter={(value, name) => [formatScalarValue(value), metricDisplayName(name)]}
              labelFormatter={(label, payload) => payload?.[0]?.payload?.fullVersion || label}
            />
            <Legend />
            {metrics.map((metric, index) => (
              <Line
                key={metric}
                type="monotone"
                dataKey={metric}
                name={metricDisplayName(metric)}
                stroke={CHART_PALETTE[index % CHART_PALETTE.length]}
                strokeWidth={2.25}
                dot={{ r: 3 }}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}


function MultiMetricBarChart({ rows, metrics, title, description, xKey = 'library' }) {
  if (!rows.length || !metrics.length) {
    return (
      <ChartPanel title={title} description={description}>
        <EmptyChartState>No numeric values are available for a comparison chart.</EmptyChartState>
      </ChartPanel>
    );
  }

  return (
    <ChartPanel title={title} description={description}>
      <div className="chartFrame">
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={rows} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey={xKey} tick={{ fontSize: 11 }} />
            <YAxis tickFormatter={formatCompactChartNumber} width={72} />
            <Tooltip formatter={(value, name) => [formatScalarValue(value), metricDisplayName(name)]} />
            <Legend />
            {metrics.map((metric, index) => (
              <Bar
                key={metric}
                dataKey={metric}
                name={metricDisplayName(metric)}
                fill={CHART_PALETTE[index % CHART_PALETTE.length]}
                radius={[6, 6, 0, 0]}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}

function LibraryComparisonChart({ data }) {
  const { rows, metrics } = buildLibraryComparisonChartData(data);
  return (
    <MultiMetricBarChart
      rows={rows}
      metrics={metrics}
      title="Library comparison chart"
      description="Numeric selected metrics for each matched library in the selected iOS scope."
    />
  );
}

function VersionComparisonChart({ data }) {
  const { rows, metrics } = buildComparisonChartData(data);
  return (
    <MultiMetricLineChart
      rows={rows}
      metrics={metrics}
      title="Version evolution chart"
      description="Numeric selected metrics across the matched iOS version observations."
    />
  );
}

function BandCountsChart({ rows }) {
  if (!rows.length) {
    return (
      <ChartPanel title="Band distribution" description="Low, medium, and high static-complexity band counts.">
        <EmptyChartState>No band count data is available.</EmptyChartState>
      </ChartPanel>
    );
  }

  return (
    <ChartPanel title="Band distribution" description="Low, medium, and high static-complexity band counts.">
      <div className="chartFrame small">
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={rows} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="band" />
            <YAxis allowDecimals={false} width={56} />
            <Tooltip formatter={(value) => [formatScalarValue(value), 'Libraries']} />
            <Bar dataKey="count" name="Libraries" fill={CHART_PALETTE[1]} radius={[8, 8, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}

function TopScoresChart({ rows }) {
  if (!rows.length) {
    return (
      <ChartPanel title="Top libraries by score" description="Highest heuristic static scores in the selected iOS version.">
        <EmptyChartState>No score data is available.</EmptyChartState>
      </ChartPanel>
    );
  }

  return (
    <ChartPanel title="Top libraries by score" description="Highest heuristic static scores in the selected iOS version.">
      <div className="chartFrame tall">
        <ResponsiveContainer width="100%" height={360}>
          <BarChart data={rows} layout="vertical" margin={{ top: 12, right: 24, left: 24, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis type="number" domain={[0, 100]} />
            <YAxis dataKey="library" type="category" width={210} tick={{ fontSize: 11 }} />
            <Tooltip formatter={(value) => [formatScalarValue(value), 'Score']} />
            <Bar dataKey="score" name="Score" fill={CHART_PALETTE[0]} radius={[0, 8, 8, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}

function PublishedDashboards() {
  return (
    <Card title="Published Plotly dashboards">
      <p className="note">
        These are the full generated Plotly dashboards published through GitHub Pages. Use them for broad exploration.
        Contextual charts are shown directly in the Library Explorer, comparison, and iOS summary sections.
      </p>
      <div className="dashboardGrid">
        {PUBLISHED_PLOTS.map((plot) => {
          const url = `${PUBLISHED_PLOT_BASE_URL}/${plot.path}`;
          return (
            <div className="dashboardCard" key={plot.path}>
              <h3>{plot.title}</h3>
              <p>{plot.description}</p>
              <a href={url} target="_blank" rel="noreferrer">Open dashboard</a>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function Overview({ health, versionCount, libraryCount, selectedDataset, datasets, authState }) {
  const selectedDatasetInfo = datasets.find((item) => item.name === selectedDataset);

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
          <div className="contextStrip">
            <span>Active dataset: <strong>{selectedDataset}</strong></span>
            <span>Auth: <strong>{authState.configured ? (authState.authenticated ? 'anonymous session active' : 'configured, not authenticated') : 'not configured'}</strong></span>
            {selectedDatasetInfo?.trust_level ? <span>Trust: <strong>{selectedDatasetInfo.trust_level}</strong></span> : null}
          </div>
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

function DatasetSelector({ datasets, selectedDataset, onChange, authState }) {
  const selected = datasets.find((item) => item.name === selectedDataset);

  return (
    <Card title="Dataset scope">
      <div className="datasetScopeGrid">
        <label>
          Dataset
          <select value={selectedDataset} onChange={(event) => onChange(event.target.value)}>
            {datasets.length ? datasets.map((dataset) => (
              <option key={dataset.name} value={dataset.name}>{datasetLabel(dataset)}</option>
            )) : <option value={DEFAULT_DATASET}>{DEFAULT_DATASET}</option>}
          </select>
        </label>
        <div className="datasetMeta">
          <span>Visibility: <strong>{selected?.visibility || 'public'}</strong></span>
          <span>Source: <strong>{selected?.source_type || 'public_baseline'}</strong></span>
          <span>Trust: <strong>{selected?.trust_level || 'verified_pipeline_output'}</strong></span>
        </div>
      </div>
      <p className="note">
        Public data is available without a user session. Private user datasets become visible when the browser has an anonymous Supabase Auth session.
      </p>
      {!authState.configured ? (
        <p className="warningNote">
          Supabase Auth is not configured for this UI deployment. Only public datasets will be available.
        </p>
      ) : null}
      {selected?.trust_level === 'user_provided_unverified' ? (
        <p className="warningNote">
          User-provided observations are not independently verified by DylibScope. Scores, summaries, comparisons, and security indicators are computed from the values entered by the user.
        </p>
      ) : null}
    </Card>
  );
}

function LibraryExplorer({ libraries, versions, datasetName }) {
  const [library, setLibrary] = useState('libsqlite3.0.dylib');
  const [iosVersion, setIosVersion] = useState('');
  const [selectedMetrics, setSelectedMetrics] = useState([]);
  const [libraryVersionChoices, setLibraryVersionChoices] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [chartMetric, setChartMetric] = useState(DEFAULT_TIMELINE_METRIC);
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
          dataset_name: datasetName,
        });
        if (cancelled) return;
        const timelineRows = response.timeline || [];
        const choices = buildObservationVersionChoices(timelineRows);
        setTimeline(timelineRows);
        setChartMetric(chooseTimelineMetric(timelineRows));
        setLibraryVersionChoices(choices);
        if (choices.length && !choices.some((choice) => choice.value === iosVersion)) {
          setIosVersion(choices[0].value);
        }
      } catch (_) {
        if (!cancelled) {
          setLibraryVersionChoices([]);
          setTimeline([]);
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
  }, [library, datasetName]);

  async function loadLibrary() {
    setLoading(true);
    setError('');
    setData(null);
    setReport(null);
    try {
      const metricQuery = {
        dataset_name: datasetName,
        ios_version: iosVersion || undefined,
        metrics: buildMetricQuery(selectedMetrics),
      };
      const reportQuery = {
        dataset_name: datasetName,
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
  const availableTimelineMetricOptions = useMemo(() => buildTimelineMetricOptions(timeline), [timeline]);
  const timelineChartRows = useMemo(() => buildTimelineChartRows(timeline, chartMetric), [timeline, chartMetric]);
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
      {timeline.length ? (
        <div className="contextChartBlock">
          <div className="chartControlRow">
            <label className="compactChartControl">
              Timeline metric
              <select value={chartMetric} onChange={(event) => setChartMetric(event.target.value)}>
                {availableTimelineMetricOptions.map((item) => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </select>
            </label>
            <p className="muted">{metricInterpretation(chartMetric)}</p>
          </div>
          <MetricTimelineChart
            rows={timelineChartRows}
            metricName={chartMetric}
            title="Library metric evolution"
            description={`${library} across available iOS version observations.`}
          />
        </div>
      ) : null}
      <MetricSelector selected={selectedMetrics} onChange={setSelectedMetrics} />
      <LoadingButton loading={loading} disabled={!library || !iosVersion} onClick={loadLibrary}>Load metrics and report</LoadingButton>
      <ErrorBox error={error} />
      {metricEntries.length ? (
        <section className="libraryResultSection">
          <h3>Selected metrics</h3>
          <p className="sectionIntro">
            {selectedMetrics.length
              ? 'Showing only the metrics selected above. The full security report below is still computed from the complete weighted metric profile for this library/version.'
              : 'Showing all metrics returned for this library/version.'}
          </p>
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
        </section>
      ) : null}
      {scorePayload ? (
        <section className="libraryResultSection fullSecurityReport">
          <h3>Full security report</h3>
          <p className="sectionIntro">
            This score is computed from the complete weighted metric profile for this library/version, not only from the selected metrics shown above.
          </p>
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
          {scorePayload.risk_points?.length ? (
            <div>
              <h3>Risk points</h3>
              <div className="tagRow">
                {scorePayload.risk_points.map((point) => <span className="tag" key={point}>{point}</span>)}
              </div>
            </div>
          ) : null}
          {scorePayload.top_contributors?.length ? (
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
        </section>
      ) : null}
    </Card>
  );
}

function CompareLibraries({ libraries, versions, datasetName }) {
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
        dataset_name: datasetName,
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
      {data ? <LibraryComparisonChart data={data} /> : null}
      {data ? <ComparisonResults data={data} /> : null}
    </Card>
  );
}

function CompareVersions({ libraries, datasetName }) {
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
          dataset_name: datasetName,
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
  }, [library, datasetName]);

  async function compare() {
    setLoading(true);
    setError('');
    setData(null);
    try {
      const response = await apiPost(`/v1/libraries/${encodeURIComponent(library)}/compare-versions`, {
        dataset_name: datasetName,
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
      {data ? <VersionComparisonChart data={data} /> : null}
      {data ? <ComparisonResults data={data} showDelta /> : null}
    </Card>
  );
}

function VersionSummary({ versions, datasetName }) {
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
        dataset_name: datasetName,
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
          <div className="chartGrid">
            <BandCountsChart rows={buildBandChartRows(data)} />
            <TopScoresChart rows={buildTopScoreRows(data)} />
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
  const [datasets, setDatasets] = useState([]);
  const [selectedDataset, setSelectedDataset] = useState(DEFAULT_DATASET);
  const [loadError, setLoadError] = useState('');
  const [authState, setAuthState] = useState({
    configured: authConfigured,
    loading: true,
    authenticated: false,
    userId: null,
    isAnonymous: false,
    error: '',
  });

  useEffect(() => {
    let cancelled = false;

    async function initializeAuth() {
      const result = await ensureAnonymousSession();
      if (cancelled) return;

      if (result.session?.access_token) {
        setApiAuthToken(result.session.access_token);
      }

      setAuthState({
        configured: result.configured,
        loading: false,
        authenticated: Boolean(result.session?.access_token),
        userId: result.user?.id || null,
        isAnonymous: Boolean(result.user?.is_anonymous || result.user?.app_metadata?.provider === 'anonymous'),
        error: result.error?.message || '',
      });
    }

    initializeAuth();

    const subscription = onAuthStateChange((session) => {
      setApiAuthToken(session?.access_token || null);
      setAuthState((current) => ({
        ...current,
        loading: false,
        authenticated: Boolean(session?.access_token),
        userId: session?.user?.id || null,
        isAnonymous: Boolean(session?.user?.is_anonymous || session?.user?.app_metadata?.provider === 'anonymous'),
        error: '',
      }));
    });

    return () => {
      cancelled = true;
      subscription?.unsubscribe?.();
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadDatasets() {
      try {
        const response = await apiGet('/v1/datasets');
        if (cancelled) return;
        const availableDatasets = response.datasets || [];
        setDatasets(availableDatasets);
        if (availableDatasets.length && !availableDatasets.some((dataset) => dataset.name === selectedDataset)) {
          setSelectedDataset(availableDatasets[0].name);
        }
      } catch (err) {
        if (!cancelled) {
          setLoadError(err.message);
          setDatasets([{ name: DEFAULT_DATASET, visibility: 'public', source_type: 'public_baseline', trust_level: 'verified_pipeline_output' }]);
        }
      }
    }

    if (!authState.loading) {
      loadDatasets();
    }

    return () => {
      cancelled = true;
    };
  }, [authState.loading, authState.authenticated]);

  useEffect(() => {
    let cancelled = false;

    async function loadDatasetScopedData() {
      setLoadError('');
      try {
        const [healthResponse, librariesResponse, versionsResponse] = await Promise.all([
          apiGet('/health'),
          apiGet('/v1/libraries', { dataset_name: selectedDataset }),
          apiGet('/v1/ios-versions'),
        ]);
        if (cancelled) return;
        setHealth(healthResponse);
        setLibraries(librariesResponse.libraries || []);
        setVersions(versionsResponse.ios_versions || []);
      } catch (err) {
        if (!cancelled) {
          setLoadError(err.message);
          setLibraries([]);
          setVersions([]);
        }
      }
    }

    if (!authState.loading && selectedDataset) {
      loadDatasetScopedData();
    }

    return () => {
      cancelled = true;
    };
  }, [authState.loading, authState.authenticated, selectedDataset]);

  return (
    <main>
      <header className="topBar">
        <div>
          <h1>DylibScope</h1>
          <p>Static security trend analysis of iOS dynamic libraries</p>
        </div>
        <a href={`${API_BASE_URL}/docs`} target="_blank" rel="noreferrer">API docs</a>
      </header>
      <ErrorBox error={loadError || authState.error} />
      <Overview
        health={health}
        libraryCount={libraries.length}
        versionCount={versions.length}
        selectedDataset={selectedDataset}
        datasets={datasets}
        authState={authState}
      />
      <DatasetSelector
        datasets={datasets}
        selectedDataset={selectedDataset}
        onChange={setSelectedDataset}
        authState={authState}
      />
      {isUserProvidedDataset(selectedDataset, datasets) ? (
        <div className="userDatasetBanner">
          User-provided dataset selected. DylibScope will compute scores and security summaries from user-provided values, which may be incomplete or incorrect.
        </div>
      ) : null}
      <PublishedDashboards />
      <LibraryExplorer libraries={libraries} versions={versions} datasetName={selectedDataset} />
      <CompareLibraries libraries={libraries} versions={versions} datasetName={selectedDataset} />
      <CompareVersions libraries={libraries} datasetName={selectedDataset} />
      <VersionSummary versions={versions} datasetName={selectedDataset} />
      <MetricReference />
    </main>
  );
}
