# Copyright (c) 2021-2025 OVT LLC, https://www.ovtsolutions.ru
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import hmac
import hashlib
import json
import urllib.parse

from abc import abstractmethod
from oslo_concurrency import lockutils
from webob import Request
from datetime import datetime, timezone

SCHEME = 'AWS4'
SIGNATURE_ALGORITHM = 'HMAC-SHA256'
HTTP_HEADER_X_AMZ_DATE = 'x-amz-date'
HTTP_HEADER_X_AMZ_CONTENT_SHA256 = 'x-amz-content-sha256'

UTF_8_ENCODING = 'utf-8'
DATE_STAMP_FORMAT = "%Y%m%d"
X_AMZ_DATE_FORMAT = '%Y%m%dT%H%M%SZ'

class AbstractSignerForAuthorizationHeader:
    def __init__(self, scheme:str, region_name:str, service_name:str, terminator:str):
        self.scheme:str = scheme
        self.region_name:str = region_name
        self.service_name:str = service_name
        self.terminator = terminator

    @lockutils.synchronized('header_signature')
    def compute(self, access_key:str, method:str, path:str, headers:dict, parameters:dict, body_content:str=''):
        """
        :param access_key:
        :param method:
        :param path:
        :param headers:
        :param parameters:
        :param body_content:
        :return:
        """
        if access_key is None or not access_key:
            access_key = self.hash('')

        time_stamp = datetime.now(timezone.utc)
        date_stamp = time_stamp.strftime(DATE_STAMP_FORMAT)

        secret = self.scheme + self.get_secret_key(access_key)
        scope = access_key + "/" + date_stamp + "/" + self.region_name + "/" + self.service_name + "/" + self.terminator
        headers[HTTP_HEADER_X_AMZ_DATE] = time_stamp.strftime(X_AMZ_DATE_FORMAT)

        headers[HTTP_HEADER_X_AMZ_CONTENT_SHA256] = self.hash(body_content)

        canonicalized_header_names = self.__canonicalized_header_names(headers)
        canonicalized_headers = self.__canonicalized_header_string(headers)
        canonical_request = self.__get_client_canonical_request(
            path=self.get_path_header(path),
            http_method=method,
            query_parameters=self.get_query_parameters_header(parameters),
            canonicalized_header_names=canonicalized_header_names,
            canonicalized_headers=canonicalized_headers,
            body_hash=self.hash(body_content))

        string_to_sign = self.__get_string_to_sign(self.scheme, SIGNATURE_ALGORITHM, headers[HTTP_HEADER_X_AMZ_DATE], scope, canonical_request)

        date_key = hmac.new(secret.encode(UTF_8_ENCODING), headers[HTTP_HEADER_X_AMZ_DATE].encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        date_region_key = hmac.new(date_key.encode(UTF_8_ENCODING), self.region_name.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        date_region_service_key = hmac.new(date_region_key.encode(UTF_8_ENCODING), self.region_name.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        signing_key = hmac.new(date_region_service_key.encode(UTF_8_ENCODING), self.terminator.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()

        signature = hmac.new(signing_key.encode(UTF_8_ENCODING), string_to_sign.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()

        credentials_authorization_header = "Credential=" + scope
        signed_headers_authorization_header  = "SignedHeaders=" + canonicalized_header_names
        signature_authorization_header = "Signature=" + signature

        authorization = (self.scheme + '-' + SIGNATURE_ALGORITHM + ' ' + credentials_authorization_header + ", " +
                         signed_headers_authorization_header + ", " + signature_authorization_header )

        headers['Authorization'] = authorization

        return headers

    def verify_by_request(self, req:Request) -> int:
        headers = {}
        for header, value in req.headers.items():
            if header.lower().startswith("x-"):
                headers[header.strip().lower()] = value
        else:
            headers[header.strip()] = value

        return self.verify(
            method=req.method,
            path=req.path,
            headers=headers,
            parameters=req.params.items()
        )

    @lockutils.synchronized('header_signature')
    def verify(self, method:str, path:str, headers:dict, parameters:dict)->int:
        """
        Verifies the signature on the server side and return status 200 if signature matched, otherwise 401 or 403
        :param method:
        :param path:
        :param headers:
        :param parameters:
        :return: HTTP status
        """
        if ('Authorization' or HTTP_HEADER_X_AMZ_DATE or HTTP_HEADER_X_AMZ_CONTENT_SHA256) not in headers:
            return 401

        client_dt_str =  headers[HTTP_HEADER_X_AMZ_DATE]
        server_dt_str = datetime.now(timezone.utc).strftime(X_AMZ_DATE_FORMAT)

        client_ts = datetime.strptime(client_dt_str, X_AMZ_DATE_FORMAT).timestamp()
        server_ts = datetime.strptime(server_dt_str, X_AMZ_DATE_FORMAT).timestamp()

        if server_ts > (client_ts + (5 * 60)) or server_ts < client_ts:
            return 403

        auth_params = headers['Authorization'].split(",")
        scope = None
        client_signature= None

        for p in auth_params:
            if len(p.split('Credential=')) == 2:
                scope = p.split('Credential=')[1]
            if len(p.split('Signature='))==2:
                client_signature = p.split('Signature=')[1]

        if (scope or client_signature) is None:
            return 401

        if len(scope.split('/')) > 0:
            access_key = scope.split('/')[0]
        else:
            return 401

        secret = self.scheme + self.get_secret_key(access_key)
        canonical_request = self.__get_server_canonical_request(
            path = self.get_path_header(path),
            http_method=method,
            query_parameters = self.get_query_parameters_header(parameters),
            headers=headers
        )

        string_to_sign = self.__get_string_to_sign(self.scheme, SIGNATURE_ALGORITHM, client_dt_str, scope, canonical_request)

        date_key = hmac.new(secret.encode(UTF_8_ENCODING), client_dt_str.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        date_region_key = hmac.new(date_key.encode(UTF_8_ENCODING), self.region_name.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        date_region_service_key = hmac.new(date_region_key.encode(UTF_8_ENCODING), self.region_name.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        signing_key = hmac.new(date_region_service_key.encode(UTF_8_ENCODING), self.terminator.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        signature = hmac.new(signing_key.encode(UTF_8_ENCODING), string_to_sign.encode(UTF_8_ENCODING), hashlib.sha256).hexdigest()
        if signature == client_signature:
            return 200
        return 403

    def __get_string_to_sign(self, scheme:str, algorithm:str, date_time:str, scope:str, canonical_request:str):
        """
        Returns the string to sign
        :param scheme:
        :param algorithm:
        :param date_time:
        :param scope:
        :param canonical_request:
        :return: string to sign
        """
        result = scheme + "-" + algorithm + "\n" + date_time + "\n" + scope + "\n" + self.hash(canonical_request)
        return result

    def __get_client_canonical_request(self, path:str, http_method:str, query_parameters:str,
                                       canonicalized_header_names:str, canonicalized_headers:str, body_hash:str)->str:
        """
        Returns client's canonical request for signing
        :param path:
        :param http_method:
        :param query_parameters:
        :param canonicalized_header_names:
        :param canonicalized_headers:
        :param body_hash:
        :return: canonical request for signing
        """
        _result = (http_method + "\n" +
                   self.__canonicalized_path(path) + "\n" +
                   query_parameters + "\n" +
                   canonicalized_headers + "\n" +
                   canonicalized_header_names + "\n" +
                   body_hash)
        return _result

    def __get_server_canonical_request(self, path:str, http_method:str, query_parameters:str, headers:dict)->str:
        auth_params = headers['Authorization'].split(",")
        canonicalized_header_names = ''
        for p in auth_params:
            if len(p.split('SignedHeaders=')) == 2:
                canonicalized_header_names = str(p.split('SignedHeaders=')[1]).lower()

        canonicalized_headers = ''
        for h in canonicalized_header_names.split(";"):
            for k in headers.keys():
                if str(k).lower() == h.strip().lower():
                    canonicalized_headers += h.strip().lower() + ':' + str(headers.get(k)).strip().lower() + "\n"

        body_hash = headers[HTTP_HEADER_X_AMZ_CONTENT_SHA256]
        _result = (http_method + "\n" +
                   self.__canonicalized_path(path) + "\n" +
                   query_parameters + "\n" +
                   canonicalized_headers + "\n" +
                   canonicalized_header_names + "\n" +
                   body_hash)
        return _result

    @staticmethod
    def __canonicalized_path(path:str):
        if path is None or not path:
            return '/'
        if path.startswith("/"):
            return path
        else:
            return '/' + path

    @staticmethod
    def __canonicalized_header_names(headers:dict):
        header_keys:list = list(headers.keys())
        header_keys.sort(key=str.lower)
        _result:str = ''
        for k in header_keys:
            if len(_result) > 0:
                _result += ';'
            _result += k.lower()
        return _result

    @staticmethod
    def __canonicalized_header_string(headers:dict):
        if headers is None or not headers:
            return ''
        header_keys = list(headers.keys())
        header_keys.sort(key=str.lower)
        _buffer:str = ''
        for k in header_keys:
            _buffer += k.strip().lower() + ':' + str(headers.get(k)).strip().lower() + "\n"
        return _buffer

    @staticmethod
    def hash(canonical_value:str):
        dig = hashlib.sha256()
        dig.update(canonical_value.encode(UTF_8_ENCODING))
        return dig.hexdigest()

    @staticmethod
    def get_path_header(path:str):
        return path

    @staticmethod
    def get_query_parameters_header(query_params:dict):
        if query_params is None or not query_params:
            return ''
        sorted_query_params = dict()
        sorted_query_params_keys = sorted(query_params)
        for k in sorted_query_params_keys:
            sorted_query_params[k] = query_params.get(k)
        return urllib.parse.urlencode(sorted_query_params)

    @abstractmethod
    def get_secret_key(self, access_key:str):
        pass
