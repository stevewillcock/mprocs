use std::borrow::Cow;

use unicode_width::UnicodeWidthStr;

use crate::mprocs::{
  config::Config,
  state::{Scope, State},
};
use crate::term::{
  attrs::Attrs,
  grid::{BorderType, Rect},
  Color, Grid,
};

pub fn render_procs(
  area: Rect,
  grid: &mut Grid,
  state: &mut State,
  config: &Config,
) {
  state.procs_list.fit(area.inner(1), state.procs.len());

  if area.width <= 2 {
    return;
  }

  let active = state.scope == Scope::Procs;

  grid.draw_block(
    area.into(),
    if active {
      BorderType::Thick
    } else {
      BorderType::Plain
    },
    Attrs::default(),
  );
  let title_area = Rect {
    x: area.x + 1,
    y: area.y,
    width: area.width - 2,
    height: 1,
  };
  let r = grid.draw_text(
    title_area,
    config.proc_list_title.as_str(),
    if active {
      Attrs::default().set_bold(true)
    } else {
      Attrs::default()
    },
  );
  if state.quitting {
    let area = title_area.inner((0, 0, 0, r.width + 1));
    grid.draw_text(
      area,
      "QUITTING",
      Attrs::default()
        .fg(Color::BLACK)
        .bg(Color::RED)
        .set_bold(true),
    );
  }

  let inner_x = area.x + 1;
  let inner_width = area.width.saturating_sub(2);
  let bottom = area.y + area.height.saturating_sub(1);
  let mut y = area.y + 1;

  'procs: for index in state.procs_list.visible_range() {
    if y >= bottom {
      break;
    }
    let proc = match state.procs.get(index) {
      Some(p) => p,
      None => continue,
    };

    let selected = index == state.selected();
    let attrs = if selected {
      Attrs::default().bg(Color::Idx(240))
    } else {
      Attrs::default()
    };
    let mut row_area = Rect {
      x: inner_x,
      y,
      width: inner_width,
      height: 1,
    };

    let r = grid.draw_text(row_area, if selected { "•" } else { " " }, attrs);
    row_area.x += r.width;
    row_area.width = row_area.width.saturating_sub(r.width);

    let r = grid.draw_text(row_area, proc.name(), attrs);
    row_area.x += r.width;
    row_area.width = row_area.width.saturating_sub(r.width);

    let (status_text, status_attrs) = if proc.is_up() {
      (
        Cow::from(" UP "),
        attrs.clone().set_bold(true).fg(Color::BRIGHT_GREEN),
      )
    } else if proc.last_start.is_none() {
      (Cow::from(" IDLE "), attrs.clone())
    } else {
      match proc.exit_code() {
        Some(0) => {
          (Cow::from(" DOWN (0)"), attrs.clone().fg(Color::BRIGHT_BLUE))
        }
        Some(exit_code) => (
          Cow::from(format!(" DOWN ({})", exit_code)),
          attrs.clone().fg(Color::BRIGHT_RED),
        ),
        None => (Cow::from(" DOWN "), attrs.clone().fg(Color::BRIGHT_RED)),
      }
    };
    let status_width = status_text.width() as u16;
    let r = grid.draw_text(
      Rect {
        x: row_area.x.max(row_area.x + row_area.width - status_width),
        width: status_width.min(row_area.width),
        ..row_area
      },
      &status_text,
      status_attrs,
    );
    row_area.width = row_area.width.saturating_sub(r.width);

    grid.fill_area(row_area, ' ', attrs);
    y += 1;

    let port_attrs = attrs.clone().fg(Color::BRIGHT_YELLOW);
    for info in &proc.listening_ports {
      if y >= bottom {
        break 'procs;
      }
      let port_row = Rect {
        x: inner_x,
        y,
        width: inner_width,
        height: 1,
      };
      let text = if info.comm.is_empty() {
        format!("    :{} [{}]", info.port, info.pid)
      } else {
        format!("    :{} {}[{}]", info.port, info.comm, info.pid)
      };
      let r = grid.draw_text(port_row, &text, port_attrs);
      let remainder = Rect {
        x: port_row.x + r.width,
        width: port_row.width.saturating_sub(r.width),
        ..port_row
      };
      grid.fill_area(remainder, ' ', attrs);
      y += 1;
    }
  }
}

pub fn procs_get_clicked_index(
  area: Rect,
  x: u16,
  y: u16,
  state: &State,
) -> Option<usize> {
  if !procs_check_hit(area, x, y) {
    return None;
  }
  let inner = area.inner(1);
  let bottom = inner.y + inner.height;
  let mut row_y = inner.y;
  for index in state.procs_list.visible_range() {
    if row_y >= bottom {
      break;
    }
    let proc = state.procs.get(index)?;
    let block_rows = 1 + proc.listening_ports.len() as u16;
    let block_end = (row_y + block_rows).min(bottom);
    if y >= row_y && y < block_end {
      return Some(index);
    }
    row_y = block_end;
  }
  None
}

pub fn procs_check_hit(area: Rect, x: u16, y: u16) -> bool {
  area.x < x
    && area.x + area.width > x + 1
    && area.y < y
    && area.y + area.height > y + 1
}
