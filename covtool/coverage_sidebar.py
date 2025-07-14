"""coverage blocks sidebar widget"""

from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
)
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF, QModelIndex, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
    QLineEdit,
    QPushButton,
    QComboBox,
    QSpinBox,
    QHeaderView,
    QAbstractItemView,
)
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor

from .context import get_context
from .coverage_types import CoverageBlock, TraceFormat
from typing import List, Optional


class CoverageBlocksWidget(SidebarWidget):
    """sidebar widget for browsing coverage blocks"""

    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.bv = data
        self.frame = frame
        self.blocks: List[CoverageBlock] = []
        self.filtered_blocks: List[CoverageBlock] = []
        self.function_cache = {}  # cache block address -> function name
        self.module_cache = {}  # cache module id -> module name

        # filter debouncing
        self.filter_timer = QTimer()
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self._apply_filters)
        self.filter_timer.setInterval(300)  # 300ms delay

        # create UI elements
        self._create_ui()

        # connect to coverage context
        self._connect_coverage_signals()

        # initial update
        self._update_coverage_data()

    def _create_ui(self):
        """create the widget UI"""
        layout = QVBoxLayout()

        # header with stats
        self.stats_label = QLabel("No coverage loaded")
        self.stats_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.stats_label)

        # search box
        search_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText(
            "Filter expression (e.g. hits>10, size<0x20, func:main)"
        )
        self.search_box.textChanged.connect(self._on_filter_text_changed)
        search_layout.addWidget(self.search_box)
        layout.addLayout(search_layout)

        # coverage blocks table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Address", "Size", "Hits", "Module", "Function"]
        )

        # configure table
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # make read-only
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )

        # connect double-click to navigate
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)

        layout.addWidget(self.table)
        self.setLayout(layout)

    def _connect_coverage_signals(self):
        """connect to coverage context notifications"""
        # todo: implement actual signal connections when context supports it
        pass

    def _on_filter_text_changed(self):
        """called when filter text changes - starts debounce timer"""
        self.filter_timer.stop()
        self.filter_timer.start()

    def _update_function_cache(self):
        """update function name cache for all blocks"""
        self.function_cache.clear()
        for block in self.blocks:
            funcs = self.bv.get_functions_containing(block.address)
            if funcs:
                self.function_cache[block.address] = funcs[0].name

    def _update_module_cache(self, ctx):
        """update module name cache from trace modules"""
        self.module_cache.clear()
        if ctx.covdb.modules:
            for module_id, module_info in ctx.covdb.modules.items():
                # extract just the filename from the path
                import os

                module_name = os.path.basename(module_info.path)
                self.module_cache[module_id] = module_name

    def _update_coverage_data(self):
        """update coverage data from context"""
        if not self.bv:
            self.blocks = []
            self.stats_label.setText("No binary view active")
            self._update_table()
            return

        ctx = get_context(self.bv)
        if not ctx or not ctx.covdb.coverage_file:
            self.blocks = []
            self.stats_label.setText("No coverage loaded")
            self._update_table()
            return

        # get blocks from coverage database
        self.blocks = ctx.covdb.get_coverage_blocks()

        # update caches
        self._update_function_cache()
        self._update_module_cache(ctx)

        # update stats
        total_blocks = len(self.blocks)
        total_hits = sum(b.hitcount for b in self.blocks)
        trace_format = (
            ctx.covdb.trace_format.value if ctx.covdb.trace_format else "unknown"
        )

        self.stats_label.setText(
            f"Coverage: {total_blocks:,} blocks, {total_hits:,} hits ({trace_format})"
        )

        # apply filters and update table
        self._apply_filters()

    def _parse_filter_expression(self, expr):
        """parse filter expression like 'hits>10,size<0x20,func:main'"""
        filters = []
        if not expr.strip():
            return filters

        # split by comma
        parts = [p.strip() for p in expr.split(",")]

        for part in parts:
            if not part:
                continue

            # try different operators
            if ">" in part and part.count(">") == 1:
                parts = part.split(">", 1)
                if len(parts) == 2 and parts[0] and parts[1]:
                    filters.append((">", parts[0].strip(), parts[1].strip()))
                # else: incomplete expression, skip
            elif "<" in part and part.count("<") == 1:
                parts = part.split("<", 1)
                if len(parts) == 2 and parts[0] and parts[1]:
                    filters.append(("<", parts[0].strip(), parts[1].strip()))
                # else: incomplete expression, skip
            elif "=" in part and part.count("=") == 1:
                parts = part.split("=", 1)
                if len(parts) == 2 and parts[0] and parts[1]:
                    filters.append(("=", parts[0].strip(), parts[1].strip()))
                # else: incomplete expression, skip
            elif ":" in part and part.count(":") == 1:
                parts = part.split(":", 1)
                if len(parts) == 2 and parts[0] and parts[1]:
                    filters.append((":", parts[0].strip(), parts[1].strip()))
                # else: incomplete expression, skip
            else:
                # no operator, treat as simple text search only if it looks like plain text
                if not any(op in part for op in [">", "<", "=", ":"]):
                    filters.append(("text", part, ""))

        return filters

    def _apply_filters(self):
        """apply filter expression"""
        filter_text = self.search_box.text().strip()

        # start with all blocks
        self.filtered_blocks = self.blocks.copy()

        if not filter_text:
            self._update_table()
            return

        # parse filter expression
        filters = self._parse_filter_expression(filter_text)

        # apply each filter
        for op, field, value in filters:
            if op == "text":
                # simple text search (backward compatibility)
                text = field.lower()
                self.filtered_blocks = [
                    b
                    for b in self.filtered_blocks
                    if text in f"{b.address:x}".lower()
                    or text in self.function_cache.get(b.address, "").lower()
                ]

            elif field in ["hits", "hitcount"]:
                # parse value as int
                try:
                    val = int(value)
                    if op == ">":
                        self.filtered_blocks = [
                            b for b in self.filtered_blocks if b.hitcount > val
                        ]
                    elif op == "<":
                        self.filtered_blocks = [
                            b for b in self.filtered_blocks if b.hitcount < val
                        ]
                    elif op == "=":
                        self.filtered_blocks = [
                            b for b in self.filtered_blocks if b.hitcount == val
                        ]
                except ValueError:
                    pass  # invalid number, skip

            elif field == "size":
                # parse value as hex or int
                try:
                    val = int(value, 16) if value.startswith("0x") else int(value)
                    if op == ">":
                        self.filtered_blocks = [
                            b for b in self.filtered_blocks if b.size > val
                        ]
                    elif op == "<":
                        self.filtered_blocks = [
                            b for b in self.filtered_blocks if b.size < val
                        ]
                    elif op == "=":
                        self.filtered_blocks = [
                            b for b in self.filtered_blocks if b.size == val
                        ]
                except ValueError:
                    pass  # invalid number, skip

            elif field in ["func", "function"]:
                # function name search
                val = value.lower()
                if op in [":", "="]:
                    self.filtered_blocks = [
                        b
                        for b in self.filtered_blocks
                        if val in self.function_cache.get(b.address, "").lower()
                    ]

            elif field in ["addr", "address"]:
                # address search
                val = value.lower()
                if op in [":", "="]:
                    self.filtered_blocks = [
                        b
                        for b in self.filtered_blocks
                        if val in f"{b.address:x}".lower()
                    ]

        self._update_table()

    def _update_table(self):
        """update table with filtered blocks"""
        self.table.setRowCount(len(self.filtered_blocks))

        # get context once for module lookups
        ctx = get_context(self.bv) if self.bv else None
        show_modules = ctx and ctx.covdb.trace_format == TraceFormat.BLOCKS

        for row, block in enumerate(self.filtered_blocks):
            # address column
            addr_item = QTableWidgetItem(f"0x{block.address:x}")
            addr_item.setData(
                Qt.UserRole, block.address
            )  # store address for navigation
            self.table.setItem(row, 0, addr_item)

            # size column
            size_item = QTableWidgetItem(str(block.size))
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 1, size_item)

            # hitcount column
            hit_item = QTableWidgetItem(str(block.hitcount))
            hit_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 2, hit_item)

            # module column
            module_str = ""
            if show_modules and block.module_id is not None:
                module_str = self.module_cache.get(
                    block.module_id, f"Module {block.module_id}"
                )
            self.table.setItem(row, 3, QTableWidgetItem(module_str))

            # function column
            func_name = self.function_cache.get(block.address, "")
            self.table.setItem(row, 4, QTableWidgetItem(func_name))

    def _on_row_double_clicked(self, row, column):
        """navigate to block when row is double-clicked"""
        addr_item = self.table.item(row, 0)
        if addr_item:
            address = addr_item.data(Qt.UserRole)
            if address and self.frame:
                self.frame.navigate(self.bv, address)
                # clear selection to avoid visual glitches
                self.table.clearSelection()

    def notifyViewChanged(self, view_frame):
        """called when the view changes"""
        if view_frame is None:
            self.bv = None
        else:
            view = view_frame.getCurrentViewInterface()
            self.bv = view.getData()
            self.frame = view_frame

        self._update_coverage_data()

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


class CoverageBlocksWidgetType(SidebarWidgetType):
    """coverage blocks sidebar widget type"""

    def __init__(self):
        # create icon - "C" for coverage
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 48))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "C")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Coverage Blocks")

    def createWidget(self, frame, data):
        """create widget instance for a given context"""
        return CoverageBlocksWidget("Coverage Blocks", frame, data)

    def defaultLocation(self):
        """default location in the sidebar"""
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        """context sensitivity - self managed to detect view changes"""
        return SidebarContextSensitivity.SelfManagedSidebarContext
