//! HTML template for the Sankey topology report.

/// Renders an HTML report page with the given Sankey JSON data.
///
/// The returned HTML loads `ECharts` and `DaisyUI` from CDN.
#[allow(clippy::too_many_lines)]
pub fn render(sankey_json: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Topology — mmdb</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/daisyui@4/dist/full.min.css">
  <style>
    body        {{ display:flex; margin:0; height:100vh; overflow:hidden; }}
    aside       {{ width:14rem; flex:none; padding:1rem; overflow-y:auto; }}
    main        {{ flex:1; display:flex; flex-direction:column; min-width:0; }}
    #filter-bar {{ flex:none; padding:0.75rem 1rem; display:flex; align-items:center; gap:0.5rem; border-bottom:1px solid oklch(var(--b3)/1); }}
    #filter     {{ flex:1; max-width:24rem; }}
    #chart-wrap {{ flex:1; overflow-y:auto; padding:1rem; }}
    #chart      {{ width:100%; }}
  </style>
</head>
<body>
  <aside class="bg-base-200">
    <ul class="menu text-base-content">
      <li class="menu-title">Network</li>
      <li><a class="active">Topology</a></li>
    </ul>
  </aside>
  <main>
    <div id="filter-bar" class="bg-base-100">
      <input id="filter" type="text" placeholder="Filter by IP or CIDR… (node click to select)"
             class="input input-bordered input-sm">
      <button id="clear-btn" class="btn btn-sm btn-ghost" style="display:none">✕</button>
    </div>
    <div id="chart-wrap">
      <div id="chart"></div>
    </div>
  </main>
  <script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
  <script>
    const SANKEY_DATA = {sankey_json};

    // nodeGap must match the value passed to ECharts series below.
    const NODE_GAP = 4;

    // Precompute adjacency maps once; SANKEY_DATA is static.
    const PREDS = {{}}, SUCCS = {{}};
    for (const l of SANKEY_DATA.links) {{
      (PREDS[l.target] = PREDS[l.target] || []).push(l.source);
      (SUCCS[l.source] = SUCCS[l.source] || []).push(l.target);
    }}
    const NODE_NAMES_LC = SANKEY_DATA.nodes.map(n => n.name.toLowerCase());

    // Compute chart height so each node in the tallest column gets >= 20px.
    // Formula accounts for ECharts series padding (uses 90% of chart height)
    // and the gaps between nodes: h = (n*20 + (n-1)*nodeGap) / 0.9
    function calcHeight(data) {{
      const depths = {{}};
      let head = 0;
      const queue = ['Internet'];
      depths['Internet'] = 0;
      const adj = {{}};
      for (const l of data.links) {{
        (adj[l.source] = adj[l.source] || []).push(l.target);
      }}
      while (head < queue.length) {{
        const n = queue[head++], d = depths[n];
        for (const nb of (adj[n] || [])) {{
          if (!(nb in depths)) {{ depths[nb] = d + 1; queue.push(nb); }}
        }}
      }}
      const cnt = {{}};
      for (const v of Object.values(depths)) cnt[v] = (cnt[v] || 0) + 1;
      const maxN = Math.max(...Object.values(cnt), 1);
      const needed = Math.ceil((maxN * 20 + Math.max(0, maxN - 1) * NODE_GAP) / 0.9);
      return Math.max(Math.round(window.innerHeight * 0.85), needed);
    }}

    const chartEl  = document.getElementById('chart');
    const filterEl  = document.getElementById('filter');
    const clearBtn  = document.getElementById('clear-btn');
    const h0 = calcHeight(SANKEY_DATA);
    chartEl.style.height = h0 + 'px';
    // Pass height explicitly so ECharts does not rely on CSS reflow timing.
    const chart = echarts.init(chartEl, null, {{ height: h0 }});

    function bfsExpand(seeds, adj, nodeSet) {{
      let head = 0;
      const q = [...seeds];
      while (head < q.length) {{
        const node = q[head++];
        for (const nb of (adj[node] || [])) {{
          if (!nodeSet.has(nb)) {{ nodeSet.add(nb); q.push(nb); }}
        }}
      }}
    }}

    function applyFilter(q) {{
      filterEl.value = q;
      clearBtn.style.display = q ? '' : 'none';
      if (!q) {{ renderChart(SANKEY_DATA); return; }}
      const ql = q.toLowerCase();
      const matched = new Set(
        SANKEY_DATA.nodes.filter((_, i) => NODE_NAMES_LC[i].includes(ql)).map(n => n.name)
      );
      if (matched.size === 0) {{ renderChart({{ nodes: [], links: [] }}); return; }}
      const nodeSet = new Set(matched);
      bfsExpand(matched, PREDS, nodeSet);
      bfsExpand(matched, SUCCS, nodeSet);
      const links = SANKEY_DATA.links.filter(l => nodeSet.has(l.source) && nodeSet.has(l.target));
      renderChart({{ nodes: [...nodeSet].map(n => ({{ name: n }})), links }});
    }}

    function renderChart(data) {{
      const h = calcHeight(data);
      chartEl.style.height = h + 'px';
      chart.resize({{ height: h }});
      chart.setOption({{
        tooltip: {{
          trigger: 'item',
          backgroundColor: 'rgba(248, 250, 252, 0.97)',
          borderColor: '#2563eb',
          borderWidth: 1,
          padding: [6, 10],
          textStyle: {{ color: '#0f172a', fontSize: 13 }}
        }},
        series: [{{
          type: 'sankey',
          nodeGap: NODE_GAP,
          emphasis: {{ focus: 'adjacency' }},
          data: data.nodes,
          links: data.links
        }}]
      }});
    }}
    renderChart(SANKEY_DATA);

    // Node click: filter by the clicked node name; Internet click clears filter.
    chart.on('click', function(params) {{
      if (params.dataType === 'node') {{
        applyFilter(params.name === 'Internet' ? '' : params.name);
      }}
    }});

    filterEl.addEventListener('input', function() {{ applyFilter(this.value.trim()); }});
    clearBtn.addEventListener('click', function() {{ applyFilter(''); }});
    window.addEventListener('resize', () => chart.resize());
  </script>
</body>
</html>"#,
    )
}
