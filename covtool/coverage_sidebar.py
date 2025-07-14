"""coverage blocks sidebar widget"""

from binaryninjaui import (
    SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, 
    SidebarWidgetLocation, SidebarContextSensitivity
)
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF, QModelIndex
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget,
    QTableWidget, QTableWidgetItem, QLineEdit, QPushButton,
    QComboBox, QSpinBox, QHeaderView, QAbstractItemView
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
        self.search_box.setPlaceholderText("Search address or function...")
        self.search_box.textChanged.connect(self._apply_filters)
        search_layout.addWidget(self.search_box)
        layout.addLayout(search_layout)
        
        # coverage blocks table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Address", "Size", "Hit Count", "Module", "Function"
        ])
        
        # configure table
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # make read-only
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        
        # connect double-click to navigate
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        
        layout.addWidget(self.table)
        self.setLayout(layout)
    
    def _connect_coverage_signals(self):
        """connect to coverage context notifications"""
        # todo: implement actual signal connections when context supports it
        pass
    
    def _update_function_cache(self):
        """update function name cache for all blocks"""
        self.function_cache.clear()
        for block in self.blocks:
            funcs = self.bv.get_functions_containing(block.address)
            if funcs:
                self.function_cache[block.address] = funcs[0].name
    
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
        
        # update function cache for new blocks
        self._update_function_cache()
        
        # update stats
        total_blocks = len(self.blocks)
        total_hits = sum(b.hitcount for b in self.blocks)
        trace_format = ctx.covdb.trace_format.value if ctx.covdb.trace_format else "unknown"
        
        self.stats_label.setText(
            f"Coverage: {total_blocks:,} blocks, {total_hits:,} hits ({trace_format} format)"
        )
        
        # apply filters and update table
        self._apply_filters()
    
    def _apply_filters(self):
        """apply search filter"""
        search_text = self.search_box.text().lower()
        
        # start with all blocks
        self.filtered_blocks = self.blocks.copy()
        
        # apply search filter
        if search_text:
            filtered = []
            for block in self.filtered_blocks:
                # check address
                if search_text in f"{block.address:x}".lower():
                    filtered.append(block)
                    continue
                
                # check function name from cache
                func_name = self.function_cache.get(block.address, "")
                if func_name and search_text in func_name.lower():
                    filtered.append(block)
            
            self.filtered_blocks = filtered
        
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
            addr_item.setData(Qt.UserRole, block.address)  # store address for navigation
            self.table.setItem(row, 0, addr_item)
            
            # size column
            size_item = QTableWidgetItem(str(block.size))
            size_item.setTextAlignment(Qt.AlignRight)
            self.table.setItem(row, 1, size_item)
            
            # hitcount column
            hit_item = QTableWidgetItem(str(block.hitcount))
            hit_item.setTextAlignment(Qt.AlignRight)
            self.table.setItem(row, 2, hit_item)
            
            # module column
            module_str = ""
            if show_modules and block.module_id is not None:
                module_str = f"Module {block.module_id}"
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
                # navigate to the address
                self.frame.navigate(self.bv, address)
    
    
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