import time
import threading
from typing import Optional, Union


import requests

from app.log import logger
from app.helper.storage import StorageHelper


p115_open_lock = threading.Lock()


class U115NoCheckInException(Exception):
    """
    未登录
    """


class U115OpenHelper:
    """
    115 Open Api
    """

    _auth_state = {}

    base_url = "https://proapi.115.com"

    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self._init_session()

    def _init_session(self):
        """
        初始化带速率限制的会话
        """
        self.session.headers.update(
            {
                "User-Agent": "W115Storage/2.0",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )

    def _check_session(self):
        """
        检查会话是否过期
        """
        if not self.access_token:
            raise U115NoCheckInException("【P115Open】请先扫码登录！")

    @property
    def access_token(self) -> Optional[str]:
        """
        访问token
        """
        with p115_open_lock:
            storagehelper = StorageHelper()
            u115_info = storagehelper.get_storage(storage="u115")
            if not u115_info:
                return None
            tokens = u115_info.config
            refresh_token = tokens.get("refresh_token")
            if not refresh_token:
                return None
            expires_in = tokens.get("expires_in", 0)
            refresh_time = tokens.get("refresh_time", 0)
            if expires_in and refresh_time + expires_in < int(time.time()):
                tokens = self.__refresh_access_token(refresh_token)
                if tokens:
                    storagehelper.set_storage(
                        storage="u115",
                        conf={"refresh_time": int(time.time()), **tokens},
                    )
            access_token = tokens.get("access_token")
            if access_token:
                self.session.headers.update({"Authorization": f"Bearer {access_token}"})
            return access_token

    def __refresh_access_token(self, refresh_token: str) -> Optional[dict]:
        """
        刷新access_token
        """
        resp = self.session.post(
            "https://passportapi.115.com/open/refreshToken",
            data={"refresh_token": refresh_token},
        )
        if resp is None:
            logger.error(
                f"【P115Open】刷新 access_token 失败：refresh_token={refresh_token}"
            )
            return None
        result = resp.json()
        if result.get("code") != 0:
            logger.warn(
                f"【P115Open】刷新 access_token 失败：{result.get('code')} - {result.get('message')}！"
            )
        return result.get("data")

    def _request_api(
        self,
        method: str,
        endpoint: str,
        result_key: Optional[str] = None,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> Optional[Union[dict, list]]:
        """
        带错误处理和速率限制的API请求
        """
        # 检查会话
        self._check_session()

        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        kwargs["headers"] = request_headers

        resp = self.session.request(method, f"{self.base_url}{endpoint}", **kwargs)
        if resp is None:
            logger.warn(f"【P115Open】{method} 请求 {endpoint} 失败！")
            return None

        # 处理速率限制
        if resp.status_code == 429:
            reset_time = int(resp.headers.get("X-RateLimit-Reset", 60))
            time.sleep(reset_time + 5)
            return self._request_api(method, endpoint, result_key, **kwargs)

        # 处理请求错误
        resp.raise_for_status()

        # 返回数据
        ret_data = resp.json()
        if ret_data.get("code") != 0:
            logger.warn(
                f"【P115Open】{method} 请求 {endpoint} 出错：{ret_data.get('message')}！"
            )

        if result_key:
            return ret_data.get(result_key)
        return ret_data

    def get_download_url(
        self,
        pickcode: str,
        user_agent: str,
    ) -> Optional[str]:
        
        """
        获取下载链接
        1.拿strm中保存的pick_code，调downurl，得到源文件fid。(网络,可改为本地)
        2.拿1得到的fid，调copy，无返回值。(网络)
        3.用目标目录id，调files，得到第一个文件的pick_code。(网络)
        4.用3得到的pick_code，调downurl(网络)
        5.删除文件(网络请求)[测试结果:立马删除不行,可用定时器夜里删]
        """

        """
        1.拿strm中保存的pick_code，调downurl，得到源文件fid。
        """
        download_info = self._request_api(
            "POST",
            "/open/ufile/downurl",
            "data",
            data={"pick_code": pickcode},
            headers={"User-Agent": user_agent},
        )
        if not download_info:
            logger.erro(f"1:{download_info}")
            return None
        fid = next(iter(download_info))
        p_url = list(download_info.values())[0].get("url", {}).get("url") 
        logger.info(f"{user_agent}1.拿strm中保存的pick_code，调downurl，得到源文件fid。: {fid}")

        """
        2.拿1得到的fid，调copy，无返回值。
        """
        copy_info = self._request_api(
            "POST",
            "/open/ufile/copy",
            "state",
            data={"pid":"3205973288710831809", "file_id":fid,"nodupli":0},
            headers={"User-Agent": user_agent},
        )
        logger.info(f"{user_agent}2.拿1得到的fid，调copy，无返回值,结果: {copy_info}")
        if not copy_info:
            logger.erro(f"2: {copy_info}")
            return None
        
        """
        3.用目标目录id，调files，得到第一个文件的pick_code。(网络请求)
        """
        get_first = self._request_api(
            "GET",
            "/open/ufile/files",
            "data",
            data={"cid": "3205973288710831809","asc":0,"o":"user_utime"},
            headers={"User-Agent": user_agent},
        )
        if not get_first:
            logger.erro(f"3: {get_first}")
            return None
        first_fid = get_first[0].get("fid")
        first_pc  = get_first[0].get("pc")
        logger.info(f"{user_agent}3.copy文件夹中第一个文件的fid:{first_fid},pc: {first_pc}")

        """
        4.用3得到的pick_code，替换downurl。(本地)
        """
        new_download_info = self._request_api(
            "POST",
            "/open/ufile/downurl",
            "data",
            data={"pick_code": first_pc},
            headers={"User-Agent": user_agent},
        )
        if not new_download_info:
            logger.erro(f"4: {new_download_info}")
            return None
        
        np_url = list(new_download_info.values())[0].get("url", {}).get("url") 
        logger.info(f"{user_agent}4.url:{np_url}")

        """
        5.删除文件(网络请求)
        rm_info = self._request_api(
            "POST",
            "/open/ufile/delete",
            "state",
            data={"file_ids": first_fid},
            headers={"User-Agent": user_agent},
        )
        if not rm_info:
            logger.erro(f"5: {rm_info}")
        logger.info(f"{user_agent}5.删除文件: {rm_info}")
        """
        return np_url
