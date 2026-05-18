//! HTML template for the Sankey topology report.

/// Renders an HTML report page with the given Sankey JSON data.
///
/// The returned HTML loads `ECharts` and `DaisyUI` from CDN.
pub fn render(sankey_json: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Topology — mmdb</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/daisyui@4/dist/full.min.css">
</head>
<body>
  <div class="drawer lg:drawer-open">
    <input id="drawer-toggle" type="checkbox" class="drawer-toggle">
    <div class="drawer-content flex flex-col">
      <label for="drawer-toggle" class="btn btn-ghost lg:hidden">☰</label>
      <div class="p-4">
        <input id="filter" type="text" placeholder="Filter by IP or CIDR…"
               class="input input-bordered w-full max-w-sm mb-4">
        <div id="chart" style="width:100%;height:80vh"></div>
      </div>
    </div>
    <div class="drawer-side">
      <label for="drawer-toggle" aria-label="close sidebar" class="drawer-overlay"></label>
      <ul class="menu bg-base-200 text-base-content min-h-full w-56 p-4">
        <li class="menu-title">Network</li>
        <li><a class="active">Topology</a></li>
      </ul>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
  <script>
    const SANKEY_DATA = {sankey_json};
    const chart = echarts.init(document.getElementById('chart'));
    function renderChart(data) {{
      chart.setOption({{
        tooltip: {{ trigger: 'item' }},
        series: [{{
          type: 'sankey',
          layout: 'none',
          emphasis: {{ focus: 'adjacency' }},
          data: data.nodes,
          links: data.links
        }}]
      }});
    }}
    renderChart(SANKEY_DATA);
    document.getElementById('filter').addEventListener('input', function() {{
      const q = this.value.trim().toLowerCase();
      if (!q) {{ renderChart(SANKEY_DATA); return; }}
      const nodes = SANKEY_DATA.nodes.filter(n => n.name.toLowerCase().includes(q));
      const nodeSet = new Set(nodes.map(n => n.name));
      nodeSet.add('Internet');
      const links = SANKEY_DATA.links.filter(l => nodeSet.has(l.source) && nodeSet.has(l.target));
      renderChart({{ nodes: [...nodeSet].map(n => ({{ name: n }})), links }});
    }});
    window.addEventListener('resize', () => chart.resize());
  </script>
</body>
</html>"#,
    )
}
