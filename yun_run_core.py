# yun_run_core.py
# (这是你原来的main.py，经过了改造)
import configparser
import gzip
import hashlib
import json
import os
import random
import time
import traceback
from base64 import b64encode, b64decode
from typing import List, Dict

import gmssl.sm2 as sm2
import requests
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

from tools.drift import add_drift

# --- 全局变量 ---
# 将在 set_args 中被赋值
my_host = None
default_key = None
CipherKeyEncrypted = None
my_app_edition = None
my_token = None
my_device_id = None
my_key = None
my_device_name = None
my_sys_edition = None
my_utc = None
my_uuid = None
my_sign = None
min_distance = None
allow_overflow_distance = None
single_mileage_min_offset = None
single_mileage_max_offset = None
cadence_min_offset = None
cadence_max_offset = None
split_count = None
exclude_points = None
min_consume = None
max_consume = None
strides = None
md5key = None
platform = None
PUBLIC_KEY = None
PRIVATE_KEY = None

# 日志回调函数和停止事件，将由外部传入
log_callback = print
stop_event = None


# --- 核心函数 (基本保持原样，只是print改为log_callback) ---

# 注意：为了让这个文件能独立运行（如果需要调试），
# 我们在调用 log_callback 前检查它是否存在。
def log(message):
    if callable(log_callback):
        log_callback(str(message))


def set_args(conf_path: str):
    global my_host, default_key, CipherKeyEncrypted, my_app_edition, my_token, my_device_id
    global my_key, my_device_name, my_sys_edition, my_utc, my_uuid, my_sign
    global min_distance, allow_overflow_distance, single_mileage_min_offset, single_mileage_max_offset
    global cadence_min_offset, cadence_max_offset, split_count, exclude_points, min_consume, max_consume
    global strides, PUBLIC_KEY, PRIVATE_KEY, md5key, platform

    conf = configparser.ConfigParser()
    if not os.path.exists(conf_path):
        raise FileNotFoundError(f"配置文件未找到: {conf_path}")
    conf.read(conf_path, encoding="utf-8")

    my_host = conf.get("Yun", "school_host")
    default_key = conf.get("Yun", "cipherkey")
    CipherKeyEncrypted = conf.get("Yun", "cipherkeyencrypted")
    my_app_edition = conf.get("Yun", "app_edition")
    my_token = conf.get("User", 'token')
    my_device_id = conf.get("User", "device_id")
    my_key = conf.get("User", "map_key")
    my_device_name = conf.get("User", "device_name")
    my_sys_edition = conf.get("User", "sys_edition")
    my_utc = conf.get('User', 'utc') or str(int(time.time()))
    my_uuid = conf.get("User", "uuid")
    my_sign = conf.get("User", "sign")
    min_distance = float(conf.get("Run", "min_distance"))
    allow_overflow_distance = float(conf.get("Run", "allow_overflow_distance"))
    single_mileage_min_offset = float(conf.get("Run", "single_mileage_min_offset"))
    single_mileage_max_offset = float(conf.get("Run", "single_mileage_max_offset"))
    cadence_min_offset = int(conf.get("Run", "cadence_min_offset"))
    cadence_max_offset = int(conf.get("Run", "cadence_max_offset"))
    split_count = int(conf.get("Run", "split_count"))
    exclude_points = json.loads(conf.get("Run", "exclude_points"))
    min_consume = float(conf.get("Run", "min_consume"))
    max_consume = float(conf.get("Run", "max_consume"))
    strides = float(conf.get("Run", "strides"))
    PUBLIC_KEY = b64decode(conf.get("Yun", "PublicKey"))
    PRIVATE_KEY = b64decode(conf.get("Yun", "PrivateKey"))
    md5key = conf.get("Yun", "md5key")
    platform = conf.get("Yun", "platform")

    # 修改了这里，返回一个字典，方便外部使用
    return {
        "my_token": my_token, "my_device_id": my_device_id, "my_device_name": my_device_name,
        "my_utc": my_utc, "my_uuid": my_uuid, "my_sign": my_sign, "my_key": my_key
    }


# ... (string_to_hex, bytes_to_hex, 加密解密函数等保持不变) ...
# 我将省略这些不变的部分以节省篇幅，请确保它们在你的文件中。
def string_to_hex(input_string):
    hex_string = hex(int.from_bytes(input_string.encode(), 'big'))[2:].upper()
    return hex_string


def bytes_to_hex(input_string):
    hex_string = hex(int.from_bytes(input_string, 'big'))[2:].upper()
    return hex_string


def get_sm2_crypt():
    return sm2.CryptSM2(public_key=bytes_to_hex(PUBLIC_KEY[1:]), private_key=bytes_to_hex(PRIVATE_KEY), mode=1,
                        asn1=True)


def encrypt_sm4(value, SM_KEY, isBytes=False):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(SM_KEY, SM4_ENCRYPT)
    if not isBytes:
        encrypt_value = b64encode(crypt_sm4.crypt_ecb(value.encode("utf-8")))
    else:
        encrypt_value = b64encode(crypt_sm4.crypt_ecb(value))
    return encrypt_value.decode()


def decrypt_sm4(value, SM_KEY):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(SM_KEY, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(b64decode(value))
    return decrypt_value


def getsign(utc, uuid):
    sb = ("platform=" + platform + "&utc=" + str(utc) + "&uuid=" + str(uuid) + "&appsecret=" + md5key)
    m = hashlib.md5()
    m.update(sb.encode("utf-8"))
    return m.hexdigest()


def default_post(router, data, headers=None, m_host=None, isBytes=False, gen_sign=True):
    if m_host is None: m_host = my_host
    url = m_host + router
    if gen_sign:
        my_utc_val = str(int(time.time()))
    else:
        my_utc_val = my_utc
    sign = getsign(my_utc_val, my_uuid) if gen_sign else my_sign
    if headers is None:
        headers = {
            'token': my_token, 'isApp': 'app', 'deviceId': my_device_id, 'deviceName': my_device_name,
            'version': my_app_edition, 'platform': 'android', 'Content-Type': 'application/json; charset=utf-8',
            'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip', 'User-Agent': 'okhttp/3.12.0',
            'utc': my_utc_val, 'uuid': my_uuid, 'sign': sign
        }
    data_json = {"cipherKey": CipherKeyEncrypted, "content": encrypt_sm4(data, b64decode(default_key), isBytes=isBytes)}
    req = requests.post(url=url, data=json.dumps(data_json), headers=headers)
    req.raise_for_status()  # 抛出HTTP错误
    try:
        return decrypt_sm4(req.text, b64decode(default_key)).decode()
    except:
        return req.text


# noTokenLogin 被移除，因为登录逻辑应该由GUI处理（如果需要的话），或者预先配置好token

class Yun_For_New:
    def __init__(self, auto_generate_task=False):
        # --- 开始修改 ---
        log("正在从服务器获取跑步任务信息...")
        response_text = default_post("/run/getHomeRunInfo", "")
        log(f"服务器返回的原始信息: {response_text}")

        try:
            response_json = json.loads(response_text)
        except json.JSONDecodeError:
            raise Exception(
                f"无法解析服务器返回的信息，它不是有效的JSON格式。请检查网络或Token。返回内容: {response_text}")

        # 检查返回码是否正确
        if response_json.get('code') != 200:
            error_msg = response_json.get('msg', '未知错误')
            raise Exception(f"获取任务信息失败: {error_msg} (代码: {response_json.get('code')})。请检查Token是否有效。")

        # 安全地获取cralist，使用.get()避免KeyError
        cralist = response_json.get('data', {}).get('cralist')

        # 检查cralist是否存在并且是一个非空列表
        if not cralist or not isinstance(cralist, list) or len(cralist) == 0:
            raise Exception("错误：在服务器返回的数据中未能找到当前可用的跑步活动 ('cralist' 键为空或不存在)。\n"
                            "可能原因:\n"
                            "1. 学校当前未发布任何跑步任务。\n"
                            "2. 你的账户可能存在异常。")

        # 如果检查通过，才安全地获取数据
        data = cralist[0]
        # --- 结束修改 ---

        self.raType = data['raType']
        self.raId = data['id']
        self.strides = strides
        self.schoolId = data['schoolId']
        self.raRunArea = data['raRunArea']
        self.raDislikes = data['raDislikes']
        self.raMinDislikes = data['raDislikes']
        self.raSingleMileageMin = data['raSingleMileageMin'] + single_mileage_min_offset
        self.raSingleMileageMax = data['raSingleMileageMax'] + single_mileage_max_offset
        self.raCadenceMin = data['raCadenceMin'] + cadence_min_offset
        self.raCadenceMax = data['raCadenceMax'] + cadence_max_offset
        points = data['points'].split('|')

        # 后面的代码保持不变...
        if auto_generate_task:
            # ... (这部分逻辑保持原样)
            self.my_select_points = ""
            map_file_path = "./map.json"
            if not os.path.exists(map_file_path):
                raise FileNotFoundError(f"规划模式需要 {map_file_path} 文件，但未找到。")
            with open(map_file_path) as f:
                my_s = f.read()
                tmp = json.loads(my_s)
                self.my_select_points = tmp["mypoints"]
                self.my_point = tmp["origin_point"]
            for my_select_point in self.my_select_points:
                if my_select_point in points:
                    log(f"{my_select_point} 存在")
                else:
                    raise ValueError(f"{my_select_point} 不存在")
            log('开始标记打卡点...')
            self.now_dist = 0
            i = 0
            while (self.now_dist / 1000 > min_distance + allow_overflow_distance) or self.now_dist == 0:
                if stop_event and stop_event.is_set(): log("任务被用户终止。"); return
                i += 1
                log('第' + str(i) + '次尝试...')
                # ... (内部逻辑基本不变) ...
                self.manageList: List[Dict] = []
                self.now_dist = 0
                self.now_time = 0
                self.task_list = []
                self.task_count = 0
                self.myLikes = 0
                self.generate_task(self.my_select_points)

            self.now_time = int(random.uniform(min_consume, max_consume) * 60 * (self.now_dist / 1000))
            log('打卡点标记完成！本次将打卡' + str(self.myLikes) + '个点，处理' + str(len(self.task_list)) + '个点，总计'
                + format(self.now_dist / 1000, '.2f')
                + '公里，将耗时' + str(self.now_time // 60) + '分' + str(self.now_time % 60) + '秒')

        self.recordStartTime = ''
        self.crsRunRecordId = 0
        self.userName = ''
        self.task_map = {}

    # ... (其他方法如 generate_task, add_task 等保持不变, 只需将 print 改为 log) ...
    # 为了简洁，这里只展示需要修改停止逻辑的方法

    def do(self):
        if self.task_count <= 0:
            log("任务数量为0，无需执行do方法。")
            return
        sleep_time = self.now_time / (self.task_count + 1)
        log('总计需要休眠，每次等待' + format(sleep_time, '.2f') + '秒...')

        for task_index, task in enumerate(self.task_list):
            if stop_event and stop_event.is_set(): log("任务被用户终止。"); return
            log('开始处理第' + str(task_index + 1) + '个点...')
            for split_index, split in enumerate(task['points']):
                if stop_event and stop_event.is_set(): log("任务被用户终止。"); return
                self.split(split)
                log('  第' + str(split_index + 1) + '次splitPoint发送成功！等待' + format(sleep_time, '.2f') + '秒...')
                time.sleep(sleep_time)
            log('第' + str(task_index + 1) + '个点处理完毕！')

    def do_by_points_map(self, path='./tasks', random_choose=False, isDrift=False):
        files = os.listdir(path)
        files.sort()
        if not files:
            raise FileNotFoundError(f"任务路径 {path} 中没有找到任何task文件。")

        if not random_choose:
            # 在GUI模式下，我们总是随机选择一个，或者指定一个
            # 为简化，这里直接用随机
            file = os.path.join(path, random.choice(files))
            log("随机选择打表文件：" + file)
        else:
            file = os.path.join(path, random.choice(files))
            log("随机选择打表文件：" + file)

        with open(file, 'r', encoding='utf-8') as f:
            self.task_map = json.loads(f.read())
        if isDrift:
            log("为数据添加漂移...")
            self.task_map = add_drift(self.task_map)

        points = []
        count = 0
        total_points = len(self.task_map['data']['pointsList'])
        if total_points == 0:
            log("警告：task文件中没有点位数据。")
            return

        log(f"开始处理 {total_points} 个点位...")
        for i, point in enumerate(self.task_map['data']['pointsList']):
            if stop_event and stop_event.is_set(): log("任务被用户终止。"); return

            point_changed = {'point': point['point'], 'runStatus': '1', 'speed': point['speed'], 'isFence': 'Y',
                             'isMock': False, "runMileage": point['runMileage'], "runTime": point['runTime'],
                             "ts": str(int(time.time()))}
            points.append(point_changed)
            count += 1
            if count == split_count:
                self.split_by_points_map(points)
                sleep_time = self.task_map['data']['duration'] / total_points * split_count
                log(f"  批次发送成功 ({i + 1}/{total_points})。等待{sleep_time:.2f}秒...")
                time.sleep(sleep_time)
                count = 0
                points = []
        if count != 0:
            self.split_by_points_map(points)
            log(f"  最后批次发送成功 ({total_points}/{total_points})。")

    def start(self):
        log("准备创建云运动任务...")
        data = {'raRunArea': self.raRunArea, 'raType': self.raType, 'raId': self.raId}
        j = json.loads(default_post('/run/start', json.dumps(data)))
        if j['code'] == 200:
            self.recordStartTime = j['data']['recordStartTime']
            self.crsRunRecordId = j['data']['id']
            self.userName = j['data']['studentId']
            log("云运动任务创建成功！")
        else:
            raise Exception(f"创建任务失败: {j.get('msg', '未知错误')}")

    def split_by_points_map(self, points):
        # ... (内部逻辑不变) ...
        data = {
            "StepNumber": int(float(points[-1]['runMileage']) - float(points[0]['runMileage'])) / self.strides,
            'a': 0, 'b': None, 'c': None,
            "mileage": float(points[-1]['runMileage']) - float(points[0]['runMileage']),
            "orientationNum": 0, "runSteps": random.uniform(self.raCadenceMin, self.raCadenceMax),
            'cardPointList': points, "simulateNum": 0,
            "time": float(points[-1]['runTime']) - float(points[0]['runTime']),
            'crsRunRecordId': self.crsRunRecordId, "speeds": self.task_map['data']['recodePace'],
            'schoolId': self.schoolId, "strides": self.strides, 'userName': self.userName
        }
        resp = default_post("/run/splitPointCheating", gzip.compress(data=json.dumps(data).encode("utf-8")),
                            isBytes=True)
        log('  ' + resp)

    def finish_by_points_map(self):
        log('发送结束信号 (打表模式)...')
        # ... (内部逻辑不变) ...
        data = {
            'recordMileage': self.task_map['data']['recordMileage'],
            'recodeCadence': self.task_map['data']['recodeCadence'],
            'recodePace': self.task_map['data']['recodePace'], 'deviceName': my_device_name,
            'sysEdition': my_sys_edition, 'appEdition': my_app_edition, 'raIsStartPoint': 'Y', 'raIsEndPoint': 'Y',
            'raRunArea': self.raRunArea, 'recodeDislikes': str(self.task_map['data']['recodeDislikes']),
            'raId': str(self.raId), 'raType': self.raType, 'id': str(self.crsRunRecordId),
            'duration': self.task_map['data']['duration'], 'recordStartTime': self.recordStartTime,
            'manageList': self.task_map['data']['manageList'], 'remake': '1'}
        resp = default_post("/run/finish", json.dumps(data))
        log(resp)

    def finish(self):
        log('发送结束信号 (规划模式)...')
        # ... (内部逻辑不变) ...
        data = {
            'recordMileage': format(self.now_dist / 1000, '.2f'),
            'recodeCadence': str(random.randint(self.raCadenceMin, self.raCadenceMax)),
            'recodePace': format(self.now_time / 60 / (self.now_dist / 1000), '.2f'),
            'deviceName': my_device_name, 'sysEdition': my_sys_edition, 'appEdition': my_app_edition,
            'raIsStartPoint': 'Y', 'raIsEndPoint': 'Y', 'raRunArea': self.raRunArea,
            'recodeDislikes': str(self.myLikes), 'raId': str(self.raId), 'raType': self.raType,
            'id': str(self.crsRunRecordId), 'duration': str(self.now_time),
            'recordStartTime': self.recordStartTime, 'manageList': self.manageList, 'remake': '1'}
        resp = default_post("/run/finish", json.dumps(data))
        log(resp)


# --- 新的主入口函数 ---
def run_task(options, log_func, stop_checker):
    """
    这是由GUI调用的主任务函数。
    :param options: 一个包含所有GUI设置的字典。
    :param log_func: 用于记录日志的函数。
    :param stop_checker: 一个用于检查是否应停止的 threading.Event 对象。
    """
    global log_callback, stop_event
    log_callback = log_func
    stop_event = stop_checker

    # 改变工作目录，以防万一
    script_dir = os.path.dirname(__file__)
    if script_dir:
        os.chdir(script_dir)
        log(f"工作目录已切换到: {script_dir}")

    try:
        log("开始执行任务...")
        log("=" * 30)

        # 1. 加载配置
        log(f"加载配置文件: {options['config_path']}")
        user_info = set_args(options['config_path'])

        if not my_token:
            raise ValueError("Token为空，请在config.ini中填写token。GUI版本不支持自动登录。")

        log("配置加载成功，当前用户信息：")
        log("Token: ".ljust(15) + my_token[:10] + "...")
        log('deviceId: '.ljust(15) + my_device_id)
        log('deviceName: '.ljust(15) + my_device_name)
        log('uuid: '.ljust(15) + my_uuid)
        log("=" * 30)

        if stop_event.is_set(): return

        # 2. 根据GUI选项执行不同模式
        if options['mode'] == 'table':
            log("进入打表模式...")
            Yun = Yun_For_New(auto_generate_task=False)
            Yun.start()
            if stop_event.is_set(): return
            Yun.do_by_points_map(path=options['table_path'], random_choose=True, isDrift=options['drift'])
            if stop_event.is_set(): return
            Yun.finish_by_points_map()

        elif options['mode'] == 'plan':
            log("进入规划模式...")
            if options['quick_plan']:
                log("执行快速规划（瞬间完成）...")
                Yun = Yun_For_New(auto_generate_task=True)  # auto_generate_task=True is the key
                Yun.start()
                if stop_event.is_set(): return
                Yun.finish()
            else:
                log("执行标准规划（模拟耗时）...")
                Yun = Yun_For_New(auto_generate_task=True)
                log("起始点：[" + Yun.my_point + ']')
                Yun.start()
                if stop_event.is_set(): return
                Yun.do()
                if stop_event.is_set(): return
                Yun.finish()

        log("=" * 30)
        log("任务执行完毕！")

    except Exception as e:
        log("\n!!! 任务执行失败 !!!")
        log(f"错误类型: {type(e).__name__}")
        log(f"错误信息: {e}")
        log("详细追溯信息:")
        log(traceback.format_exc())
