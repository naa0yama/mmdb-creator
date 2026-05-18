// NOTEST(io): terminal TUI — requires interactive terminal
#![cfg_attr(coverage_nightly, coverage(off))]

//! Interactive TUI for selecting MMDB enrich fields using ratatui.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use mmdb_core::config::{EnrichConfig, EnrichField, EnrichFieldType};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use super::fields::{FieldInfo, get_by_dotpath};

/// Internal TUI state.
struct TuiState {
    /// Full list of available fields.
    items: Vec<FieldInfo>,
    /// Indices into `items` that match the current filter.
    filtered: Vec<usize>,
    /// Indices into `items` that are checked (selected).
    selected: HashSet<usize>,
    /// Cursor position within the `filtered` list.
    cursor: usize,
    /// Current filter string.
    filter: String,
    /// When true, the user is typing in the filter input.
    filter_mode: bool,
    /// Per-item output name overrides (`item_idx` → `output_name`).
    output_names: HashMap<usize, String>,
    /// Per-item type overrides (`item_idx` → [`EnrichFieldType`]).
    type_overrides: HashMap<usize, EnrichFieldType>,
    /// Global `array_join_sep` separator (default `","`).
    array_join_sep: String,
    /// When true, the user is typing in the `array_join_sep` input.
    array_join_mode: bool,
    /// When true, the user is editing `output_name` for the cursor item.
    name_edit_mode: bool,
    /// Buffer for inline `output_name` editing.
    name_edit_buf: String,
}

impl TuiState {
    fn new(items: Vec<FieldInfo>) -> Self {
        let len = items.len();
        let filtered: Vec<usize> = (0..len).collect();
        Self {
            items,
            filtered,
            selected: HashSet::new(),
            cursor: 0,
            filter: String::new(),
            filter_mode: false,
            output_names: HashMap::new(),
            type_overrides: HashMap::new(),
            array_join_sep: String::from(","),
            array_join_mode: false,
            name_edit_mode: false,
            name_edit_buf: String::new(),
        }
    }

    /// Pre-populate selection state from an existing `EnrichConfig`.
    fn populate_from_existing(&mut self, existing: &EnrichConfig) {
        self.array_join_sep.clone_from(&existing.array_join_sep);
        for ef in &existing.fields {
            // Find the item whose path matches ef.field.
            if let Some(idx) = self.items.iter().position(|f| f.path == ef.field) {
                self.selected.insert(idx);
                if let Some(ref name) = ef.output_name {
                    self.output_names.insert(idx, name.clone());
                }
                if ef.field_type != EnrichFieldType::Auto {
                    self.type_overrides.insert(idx, ef.field_type);
                }
            }
        }
    }

    /// Rebuild `filtered` from `items` using the current `filter` string.
    fn apply_filter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.filtered = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, f)| needle.is_empty() || f.path.to_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect();
        // Clamp cursor to the new list length.
        let max = self.filtered.len().saturating_sub(1);
        if self.cursor > max {
            self.cursor = max;
        }
    }

    /// Move cursor up by one.
    const fn cursor_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move cursor down by one.
    #[allow(clippy::arithmetic_side_effects)]
    const fn cursor_down(&mut self) {
        let max = self.filtered.len().saturating_sub(1);
        if self.cursor < max {
            self.cursor += 1;
        }
    }

    /// Toggle the checked state for the item at the current cursor position.
    fn toggle_current(&mut self) {
        let Some(&item_idx) = self.filtered.get(self.cursor) else {
            return;
        };
        let field_path = self
            .items
            .get(item_idx)
            .map(|f| f.path.clone())
            .unwrap_or_default();
        let is_object = self
            .items
            .get(item_idx)
            .is_some_and(|f| f.type_tag == "object");

        // Collect descendants once; reuse for both select and deselect branches.
        let descendants: Vec<usize> = if is_object {
            let prefix = format!("{field_path}.");
            self.items
                .iter()
                .enumerate()
                .filter(|(_, f)| f.path.starts_with(&prefix))
                .map(|(i, _)| i)
                .collect()
        } else {
            Vec::new()
        };

        if self.selected.contains(&item_idx) {
            self.selected.remove(&item_idx);
            for d in descendants {
                self.selected.remove(&d);
            }
        } else {
            self.selected.insert(item_idx);
            for d in descendants {
                self.selected.insert(d);
            }
        }
    }

    /// Build the [`EnrichConfig`] from the current selection state.
    ///
    /// Object-typed fields are excluded — they are a TUI-only cascade convenience
    /// and should not be persisted to config.
    fn build_config(&self) -> EnrichConfig {
        let fields: Vec<EnrichField> = self
            .items
            .iter()
            .enumerate()
            .filter(|(i, f)| self.selected.contains(i) && f.type_tag != "object")
            .map(|(i, f)| EnrichField {
                field: f.path.clone(),
                output_name: self.output_names.get(&i).cloned(),
                field_type: self
                    .type_overrides
                    .get(&i)
                    .copied()
                    .unwrap_or(EnrichFieldType::Auto),
            })
            .collect();
        EnrichConfig {
            array_join_sep: self.array_join_sep.clone(),
            fields,
        }
    }
}

/// Format a JSON value as a short display string (truncated to 40 chars).
fn format_value(value: &serde_json::Value) -> String {
    let raw = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::from("null"),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => value.to_string(),
    };
    if raw.chars().count() > 40 {
        let truncated: String = raw.chars().take(39).collect();
        format!("{truncated}…")
    } else {
        raw
    }
}

/// Draw the full TUI layout.
#[allow(clippy::too_many_lines, clippy::indexing_slicing)]
fn draw(frame: &mut Frame<'_>, state: &TuiState, sample: &serde_json::Value) {
    let area = frame.area();

    // Split: status bar at bottom (1 line), content above.
    let vertical = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(area);

    let content_area = vertical[0];
    let status_area = vertical[1];

    // Split content horizontally 50/50.
    let horizontal = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content_area);

    let left_area = horizontal[0];
    let right_area = horizontal[1];

    // --- Status bar ---
    let status_text = if state.filter_mode {
        format!("FILTER: {}  Esc=cancel", state.filter)
    } else if state.array_join_mode {
        format!("ARRAY_JOIN_SEP: {}  Esc=cancel/clear", state.array_join_sep)
    } else if state.name_edit_mode {
        format!(
            "OUTPUT_NAME: {}  Esc=cancel  Enter=confirm",
            state.name_edit_buf
        )
    } else {
        let join_str = format!("\"{}\"", state.array_join_sep);
        format!(
            "↑↓ move  Spc toggle  / filter  a sep({join_str})  t type  n rename  Enter confirm  q quit"
        )
    };
    let status = Paragraph::new(status_text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(status, status_area);

    // --- Left pane: field list ---
    let filter_title = if state.filter.is_empty() {
        String::from("Fields")
    } else {
        format!("Fields [/{}]", state.filter)
    };
    let block_left = Block::default()
        .borders(Borders::ALL)
        .title(filter_title.as_str());

    let inner_left = block_left.inner(left_area);
    frame.render_widget(block_left, left_area);

    // Visible height for the list.
    let list_height = usize::from(inner_left.height);

    // Compute scroll offset so cursor is always visible.
    let scroll_offset = if state.cursor >= list_height {
        state.cursor.saturating_sub(list_height.saturating_sub(1))
    } else {
        0
    };

    // Three columns: [x] path | type (10) | output_name (20).
    let type_col_w: u16 = 10;
    let name_col_w: u16 = 20;
    // Path column width = inner width minus the two fixed columns.
    let fixed_cols_w = usize::from(type_col_w).saturating_add(usize::from(name_col_w));
    let path_col_w = usize::from(inner_left.width)
        .saturating_sub(fixed_cols_w)
        .max(6);

    let field_rows: Vec<Row<'_>> = state
        .filtered
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(list_height)
        .map(|(display_idx, &item_idx)| {
            let field = state.items.get(item_idx);
            let path = field.map_or("", |f| f.path.as_str());
            let type_tag = field.map_or("", |f| f.type_tag);
            let is_checked = state.selected.contains(&item_idx);
            let check = if is_checked { "x" } else { " " };
            let is_cursor = display_idx == state.cursor;

            let effective_type = state
                .type_overrides
                .get(&item_idx)
                .map_or(type_tag, |ft| ft.as_str())
                .to_owned();

            // output_name column: only show for checked items.
            let output_name = if is_checked {
                state
                    .output_names
                    .get(&item_idx)
                    .cloned()
                    .unwrap_or_default()
            } else {
                String::new()
            };

            // Truncate path to fit within path_col_w (accounts for "[x] " prefix = 4 chars).
            let avail = path_col_w.saturating_sub(4);
            let path_cell = if path.len() > avail && avail > 1 {
                format!("[{check}] {}…", &path[..avail.saturating_sub(1)])
            } else {
                format!("[{check}] {path}")
            };

            let style = if is_cursor {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else if is_checked {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(path_cell),
                Cell::from(effective_type),
                Cell::from(output_name),
            ])
            .style(style)
        })
        .collect();

    let field_table = Table::new(
        field_rows,
        [
            Constraint::Min(6),
            Constraint::Length(type_col_w),
            Constraint::Length(name_col_w),
        ],
    );
    frame.render_widget(field_table, inner_left);

    // --- Right pane: preview table ---
    let block_right = Block::default().borders(Borders::ALL).title("Preview");

    let inner_right = block_right.inner(right_area);
    frame.render_widget(block_right, right_area);

    let header = Row::new(vec![
        Cell::from("Key").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Value").style(Style::default().add_modifier(Modifier::BOLD)),
    ]);

    let rows: Vec<Row<'_>> = state
        .items
        .iter()
        .enumerate()
        .filter(|(i, _)| state.selected.contains(i))
        .map(|(_, field)| {
            let val_str =
                get_by_dotpath(sample, &field.path).map_or_else(|| String::from("-"), format_value);
            // Truncate key to fit.
            let key_width = 20usize;
            let key = if field.path.len() > key_width {
                format!(
                    "…{}",
                    &field.path[field.path.len().saturating_sub(key_width.saturating_sub(1))..]
                )
            } else {
                field.path.clone()
            };
            Row::new(vec![Cell::from(key), Cell::from(val_str)])
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(40), Constraint::Percentage(60)],
    )
    .header(header)
    .block(Block::default());

    frame.render_widget(table, inner_right);
}

/// Inner event loop — runs until user confirms or quits.
///
/// Returns `Ok(Some(config))` on Enter, `Ok(None)` on q/Esc.
///
/// # Errors
///
/// Returns an error if terminal I/O fails.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
fn event_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    state: &mut TuiState,
    sample: &serde_json::Value,
) -> Result<Option<EnrichConfig>> {
    loop {
        terminal.draw(|frame| draw(frame, state, sample))?;

        let ev = event::read()?;
        let Event::Key(key) = ev else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        // --- name_edit input mode ---
        if state.name_edit_mode {
            match key.code {
                KeyCode::Esc => {
                    state.name_edit_mode = false;
                    state.name_edit_buf.clear();
                }
                KeyCode::Enter => {
                    let Some(&item_idx) = state.filtered.get(state.cursor) else {
                        state.name_edit_mode = false;
                        state.name_edit_buf.clear();
                        continue;
                    };
                    let name = state.name_edit_buf.trim().to_owned();
                    if name.is_empty() {
                        state.output_names.remove(&item_idx);
                    } else {
                        state.output_names.insert(item_idx, name);
                    }
                    state.name_edit_mode = false;
                    state.name_edit_buf.clear();
                }
                KeyCode::Backspace => {
                    state.name_edit_buf.pop();
                }
                KeyCode::Char(c) => {
                    state.name_edit_buf.push(c);
                }
                _ => {}
            }
            continue;
        }

        // --- array_join input mode ---
        if state.array_join_mode {
            match key.code {
                KeyCode::Esc => {
                    state.array_join_sep = String::from(",");
                    state.array_join_mode = false;
                }
                KeyCode::Enter => {
                    state.array_join_mode = false;
                }
                KeyCode::Backspace => {
                    state.array_join_sep.pop();
                }
                KeyCode::Char(c) => {
                    state.array_join_sep.push(c);
                }
                _ => {}
            }
            continue;
        }

        // --- filter input mode ---
        if state.filter_mode {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    state.filter_mode = false;
                }
                KeyCode::Backspace => {
                    state.filter.pop();
                    state.apply_filter();
                }
                KeyCode::Char(c) => {
                    state.filter.push(c);
                    state.apply_filter();
                }
                _ => {}
            }
            continue;
        }

        // --- normal mode ---
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => state.cursor_up(),
            KeyCode::Down | KeyCode::Char('j') => state.cursor_down(),
            KeyCode::Char(' ') => state.toggle_current(),
            KeyCode::Char('/') => {
                state.filter_mode = true;
            }
            KeyCode::Char('a') => {
                state.array_join_mode = true;
            }
            KeyCode::Char('t') => {
                // Cycle EnrichFieldType for cursor item (only if selected).
                let Some(&item_idx) = state.filtered.get(state.cursor) else {
                    continue;
                };
                if !state.selected.contains(&item_idx) {
                    continue;
                }
                let source_type = state.items.get(item_idx).map_or("string", |f| f.type_tag);
                let current = state
                    .type_overrides
                    .get(&item_idx)
                    .copied()
                    .unwrap_or(EnrichFieldType::Auto);
                let next = match (source_type, current) {
                    // list: auto → array_join → string → auto
                    ("list", EnrichFieldType::Auto) => EnrichFieldType::ArrayJoin,
                    ("list", EnrichFieldType::ArrayJoin) => EnrichFieldType::String,
                    ("list", _) => EnrichFieldType::Auto,
                    // other: auto → string → integer → bool → auto
                    (_, EnrichFieldType::Auto) => EnrichFieldType::String,
                    (_, EnrichFieldType::String) => EnrichFieldType::Integer,
                    (_, EnrichFieldType::Integer) => EnrichFieldType::Bool,
                    (_, EnrichFieldType::Bool | EnrichFieldType::ArrayJoin) => {
                        EnrichFieldType::Auto
                    }
                };
                state.type_overrides.insert(item_idx, next);
            }
            KeyCode::Char('n') => {
                // Enter inline output_name editing for cursor item (only if selected).
                let Some(&item_idx) = state.filtered.get(state.cursor) else {
                    continue;
                };
                if !state.selected.contains(&item_idx) {
                    continue;
                }
                state.name_edit_buf = state
                    .output_names
                    .get(&item_idx)
                    .cloned()
                    .unwrap_or_default();
                state.name_edit_mode = true;
            }
            KeyCode::Enter => {
                return Ok(Some(state.build_config()));
            }
            KeyCode::Char('q') | KeyCode::Esc => {
                return Ok(None);
            }
            _ => {}
        }
    }
}

/// Run an interactive TUI allowing the user to select fields for MMDB enrichment.
///
/// Displays a two-pane interface: a scrollable checkbox list on the left and a
/// preview table showing selected field values from `sample` on the right.
///
/// When `existing` is `Some`, the TUI is pre-populated with the current config so
/// the user can edit an existing selection.
///
/// Returns `Some(EnrichConfig)` when the user confirms with `Enter`, or `None`
/// when the user quits with `q` or `Esc`.
///
/// # Errors
///
/// Returns an error if the terminal cannot be initialised or if I/O fails
/// during the session.
// NOTEST(io): terminal TUI — requires interactive terminal
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn run_tui(
    fields: Vec<FieldInfo>,
    sample: &serde_json::Value,
    existing: Option<&EnrichConfig>,
) -> Result<Option<EnrichConfig>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();

    // On any setup failure, restore raw mode before propagating the error.
    let setup_result: Result<_> = (|| {
        execute!(stdout, EnterAlternateScreen)?;
        let backend = ratatui::backend::CrosstermBackend::new(std::io::stdout());
        ratatui::Terminal::new(backend).map_err(anyhow::Error::from)
    })();

    let mut terminal = match setup_result {
        Ok(t) => t,
        Err(e) => {
            let _ = disable_raw_mode();
            return Err(e);
        }
    };

    let mut state = TuiState::new(fields);
    if let Some(existing) = existing {
        state.populate_from_existing(existing);
    }
    let result = event_loop(&mut terminal, &mut state, sample);

    // Always clean up, regardless of result.
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);

    result
}
