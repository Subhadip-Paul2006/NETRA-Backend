//! # Human-Readable Output Formatting (`netra-cli::output::formatting`)
//!
//! Provides structured human-friendly tables, key-value summaries, and status blocks.

use crate::output::color::Colorizer;

/// Formats a clean boxed key-value block with title header.
pub fn format_box_block(title: &str, rows: &[(&str, String)], c: &Colorizer) -> String {
    let mut out = String::new();
    out.push_str(&c.bold(&format!("{title}\n")));
    out.push_str(&c.dim("─────────────────────────────────────────────────────────────\n"));

    let max_label_len = rows.iter().map(|(lbl, _)| lbl.len()).max().unwrap_or(15);

    for (label, value) in rows {
        let padding = " ".repeat(max_label_len.saturating_sub(label.len()) + 2);
        out.push_str(&format!("  {}:{}{}\n", c.cyan(label), padding, value));
    }

    out.push_str(&c.dim("─────────────────────────────────────────────────────────────"));
    out
}

/// Formats a bulleted key-value list.
pub fn format_bullet_list(title: &str, items: &[String], c: &Colorizer) -> String {
    let mut out = String::new();
    out.push_str(&c.bold(&format!("{title}\n")));
    for item in items {
        out.push_str(&format!("  • {item}\n"));
    }
    out
}
