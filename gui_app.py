import os
import sys

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QPlainTextEdit, QGroupBox, QRadioButton, QFormLayout,
    QLineEdit, QFileDialog, QCheckBox, QComboBox, QMessageBox
)

# 导入任务运行器
from task_runner import TaskRunner


class MainWindow(QMainWindow):
    # 定义一个信号，用于从主线程向工作线程发送停止请求
    request_stop = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("云运动跑步助手")
        self.setGeometry(100, 100, 700, 600)

        # 初始化UI
        self.setup_ui()
        self.setup_connections()

        # 线程相关变量
        self.thread = None
        self.worker = None

        self.update_ui_state(is_running=False)

    def setup_ui(self):
        # --- 主布局 ---
        main_layout = QVBoxLayout()

        # --- 配置组 ---
        config_group = QGroupBox("1. 基础配置")
        config_layout = QFormLayout()
        self.config_path_edit = QLineEdit("./config.ini")
        self.browse_button = QPushButton("浏览...")
        config_path_layout = QHBoxLayout()
        config_path_layout.addWidget(self.config_path_edit)
        config_path_layout.addWidget(self.browse_button)
        config_layout.addRow("配置文件路径:", config_path_layout)
        config_group.setLayout(config_layout)

        # --- 模式选择组 ---
        mode_group = QGroupBox("2. 选择跑步模式")
        mode_layout = QVBoxLayout()

        # 打表模式
        self.table_mode_radio = QRadioButton("打表模式 (使用预设路线)")
        self.table_mode_radio.setChecked(True)
        table_options_group = QGroupBox()
        table_options_layout = QFormLayout()
        self.school_combo = QComboBox()
        self.school_combo.addItems(
            ["翡翠湖校区 (tasks_fch)", "屯溪路校区 (tasks_txl)", "宣城校区 (tasks_xc)", "自定义 (tasks_else)"])
        self.drift_checkbox = QCheckBox("为数据添加随机漂移")
        table_options_layout.addRow("选择校区:", self.school_combo)
        table_options_layout.addRow(self.drift_checkbox)
        table_options_group.setLayout(table_options_layout)

        # 规划模式
        self.plan_mode_radio = QRadioButton("规划模式 (自动规划路线)")
        plan_options_group = QGroupBox()
        plan_options_layout = QFormLayout()
        self.quick_plan_checkbox = QCheckBox("快速完成 (瞬间完成，不模拟耗时)")
        plan_options_layout.addRow(self.quick_plan_checkbox)
        plan_options_group.setLayout(plan_options_layout)

        mode_layout.addWidget(self.table_mode_radio)
        mode_layout.addWidget(table_options_group)
        mode_layout.addWidget(self.plan_mode_radio)
        mode_layout.addWidget(plan_options_group)
        mode_group.setLayout(mode_layout)

        # --- 控制与日志组 ---
        control_group = QGroupBox("3. 控制与日志")
        control_layout = QVBoxLayout()
        self.log_display = QPlainTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Courier New", 10))
        self.start_button = QPushButton("开始任务")
        self.stop_button = QPushButton("停止任务")
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.log_display)
        control_layout.addLayout(button_layout)
        control_group.setLayout(control_layout)

        # 添加所有组到主布局
        main_layout.addWidget(config_group)
        main_layout.addWidget(mode_group)
        main_layout.addWidget(control_group)

        # 设置中央控件
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def setup_connections(self):
        self.browse_button.clicked.connect(self.browse_config_file)
        self.start_button.clicked.connect(self.start_task)
        self.stop_button.clicked.connect(self.stop_task)
        # 模式切换时，禁用/启用对应的选项组
        self.table_mode_radio.toggled.connect(
            lambda checked: self.school_combo.setEnabled(checked) and self.drift_checkbox.setEnabled(checked)
        )
        self.plan_mode_radio.toggled.connect(
            lambda checked: self.quick_plan_checkbox.setEnabled(checked)
        )

    def update_ui_state(self, is_running):
        """根据任务是否在运行来更新UI控件的启用/禁用状态"""
        self.start_button.setEnabled(not is_running)
        self.stop_button.setEnabled(is_running)

        # 运行时禁用所有选项
        self.config_path_edit.setEnabled(not is_running)
        self.browse_button.setEnabled(not is_running)
        self.table_mode_radio.setEnabled(not is_running)
        self.plan_mode_radio.setEnabled(not is_running)
        self.school_combo.setEnabled(not is_running and self.table_mode_radio.isChecked())
        self.drift_checkbox.setEnabled(not is_running and self.table_mode_radio.isChecked())
        self.quick_plan_checkbox.setEnabled(not is_running and self.plan_mode_radio.isChecked())

    @Slot()
    def browse_config_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择config.ini文件", "", "INI Files (*.ini)")
        if path:
            self.config_path_edit.setText(path)

    @Slot()
    def start_task(self):
        self.log_display.clear()

        # 1. 收集所有配置
        school_map = {
            "翡翠湖校区 (tasks_fch)": "./tasks_fch",
            "屯溪路校区 (tasks_txl)": "./tasks_txl",
            "宣城校区 (tasks_xc)": "./tasks_xc",
            "自定义 (tasks_else)": "./tasks_else",
        }

        options = {
            "config_path": self.config_path_edit.text(),
            "mode": "table" if self.table_mode_radio.isChecked() else "plan",
            "table_path": school_map[self.school_combo.currentText()],
            "drift": self.drift_checkbox.isChecked(),
            "quick_plan": self.quick_plan_checkbox.isChecked()
        }

        # 检查配置文件是否存在
        if not os.path.exists(options['config_path']):
            self.show_error_message("错误", f"配置文件不存在: {options['config_path']}")
            return

        self.update_ui_state(is_running=True)
        self.append_log("正在初始化后台线程...")

        # 2. 创建并启动线程
        self.thread = QThread()
        self.worker = TaskRunner(options)
        self.worker.moveToThread(self.thread)

        # 3. 连接信号和槽
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.task_finished)
        self.worker.log_message.connect(self.append_log)
        self.worker.error.connect(self.task_error)
        self.request_stop.connect(self.worker.stop)

        self.thread.start()
        self.append_log("线程已启动，任务开始执行...")

    @Slot()
    def stop_task(self):
        if self.thread and self.thread.isRunning():
            self.request_stop.emit()
            self.stop_button.setEnabled(False)
            self.stop_button.setText("正在停止...")

    @Slot()
    def task_finished(self):
        self.append_log("后台任务已结束。")
        if self.thread:
            self.thread.quit()
            self.thread.wait()

        self.thread = None
        self.worker = None

        self.update_ui_state(is_running=False)
        self.stop_button.setText("停止任务")

    @Slot(str)
    def task_error(self, error_message):
        self.append_log(f"!!! 任务出错 !!!\n{error_message}")
        self.show_error_message("任务出错", error_message)

    @Slot(str)
    def append_log(self, message):
        self.log_display.appendPlainText(message)
        self.log_display.verticalScrollBar().setValue(self.log_display.verticalScrollBar().maximum())

    def show_error_message(self, title, message):
        QMessageBox.critical(self, title, message)

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning():
            self.append_log("正在关闭窗口，请等待任务结束...")
            self.stop_task()
            self.thread.wait()
        event.accept()


if __name__ == "__main__":
    # 确保依赖已安装
    try:
        import requests
        import gmssl
        from Crypto.Util.Padding import pad
    except ImportError as e:
        print(f"缺少必要的库: {e.name}。请运行 'pip install requests gmssl pycryptodome' 进行安装。")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
