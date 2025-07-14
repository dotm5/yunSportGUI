import threading
import traceback

from PySide6.QtCore import QObject, Signal, Slot

# 导入我们改造后的核心逻辑模块
import yun_run_core


class TaskRunner(QObject):
    """
    这个Worker将在一个单独的线程中运行。
    它负责调用核心的跑步逻辑。
    """
    # 定义信号
    log_message = Signal(str)  # 用于向GUI发送日志消息
    finished = Signal()  # 任务完成时发出
    error = Signal(str)  # 发生错误时发出

    def __init__(self, options):
        """
        初始化Worker。
        :param options: 一个包含GUI所有设置的字典。
        """
        super().__init__()
        self.options = options
        self._stop_event = threading.Event()

    @Slot()
    def run(self):
        """
        线程启动时执行此方法。
        """
        try:
            # 将 self.log_message.emit 作为日志回调函数
            # 将 self._stop_event 作为停止检查器
            yun_run_core.run_task(
                options=self.options,
                log_func=self.log_message.emit,
                stop_checker=self._stop_event
            )
        except Exception as e:
            # 捕获任何未处理的异常，并发送错误信号
            error_info = f"发生未捕获的严重错误:\n{traceback.format_exc()}"
            self.error.emit(error_info)
        finally:
            # 确保任务结束后总是发射 finished 信号
            self.finished.emit()

    @Slot()
    def stop(self):
        """
        从主线程调用此方法来请求停止任务。
        """
        self.log_message.emit(">>> 收到停止请求，将在下个检查点安全退出...")
        self._stop_event.set()
