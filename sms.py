# @Time         : 19-1-8 上午10:55
# @Author       : Seven
# @File         : sms.py
# @Description  : 短信验证码发送模块


import base64
import datetime
import hmac
import json
import uuid
from requests import exceptions
import requests
from requests.utils import quote



class AliSms(object):

    @staticmethod
    def quote(text):
        return quote(text, safe='~')

    @staticmethod
    def stringify(**kwargs):
        pairs = []
        for k, v in sorted(kwargs.items()):
            pairs.append('{}={}'.format(k, v))
        return '&'.join(pairs)

    def canonicalize(self, **kwargs):
        pairs = []
        for k, v in sorted(kwargs.items()):
            pair = '{}={}'.format(self.quote(k), self.quote(v))
            pairs.append(pair)
        return self.quote('&'.join(pairs))

    def sign(self, text, secret):
        text = text.encode('utf-8')
        key = (secret + '&').encode('utf-8')
        digest = hmac.new(key, text, 'sha1').digest()
        signature = self.quote(base64.b64encode(digest))
        return signature

    def __init__(self):
        self.app_key = “SMS_APP_KEY”
        self.app_secret = “SMS_APP_SECRET”
        self.sign_name = “SMS_SIGN_NAME”
        self.action = 'SendSms'
        self.format = 'JSON'
        self.region_id = 'cn-hangzhou'
        self.signature_method = 'HMAC-SHA1'
        self.signature_version = '1.0'
        self.sms_version = '2017-05-25'
        self.domain = 'https://dysmsapi.aliyuncs.com'

    def send(self, phone, template_code, code=None, name=None):
        """
        :param phone: 手机号
        :param template_code:  模板ID
        :param name:  信息
        :param code: 自定义短信验证码
        :return:
        """
        if code:
            template_params = {
                'code': code
            }
        else:
            template_params = {
                'name': name
            }
        body = self._create_body(phone, template_code, template_params)
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
        }
        try:
            res = requests.post(self.domain, data=body, headers=headers)
        except exceptions.ConnectionError:
            return False
        return res

    def _create_body(self, phone, template_code, template_params):
        params = self._create_params(phone, template_code, template_params)
        text = 'POST&%2F&' + self.canonicalize(**params)
        signature = self.sign(text, self.app_secret)
        body = 'Signature={}&{}'.format(signature, self.stringify(**params))
        return body.encode('utf-8')

    def _create_params(self, phone, template_code, template_params):
        return {
            'AccessKeyId': self.app_key,
            'Action': self.action,
            'Format': self.format,
            'PhoneNumbers': phone,
            'RegionId': self.region_id,
            'SignName': self.sign_name,
            'SignatureMethod': self.signature_method,
            'SignatureNonce': str(uuid.uuid4()),
            'SignatureVersion': self.signature_version,
            'TemplateCode': template_code,
            'TemplateParam': json.dumps(template_params),
            'Timestamp': datetime.datetime.utcnow().isoformat("T"),
            'Version': self.sms_version,
        }


if __name__ == '__main__':
    pass
    # sms = AliSms()
    # resp = sms.send('18000000000', 'SMS_233333333', name='123456')
    # print(resp.status_code, resp.json())
