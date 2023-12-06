#!/usr/bin/python3
# coding=utf-8

#   Copyright 2023 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Route """

import datetime

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import auth  # pylint: disable=E0401


class Route:  # pylint: disable=E1101,R0903
    """
        Route Resource

        self is pointing to current Module instance

        By default routes are prefixed with module name
        Example:
        - pylon is at "https://example.com/"
        - module name is "demo"
        - route is "/"
        Route URL: https://example.com/demo/

        web.route decorator takes the same arguments as Flask route
        Note: web.route decorator must be the last decorator (at top)
    """

    @web.route("/login")
    def login(self):
        """ Login """
        target_token = flask.request.args.get("target_to", "")
        action = flask.url_for("auth_form.authorize")
        is_error = "error" in flask.request.args
        #
        return self.descriptor.render_template(
            "login.html",
            action=action,
            parameters=[
                {
                    "name": "target",
                    "value": target_token,
                },
            ],
            error=is_error,
        )

    @web.route("/authorize", methods=["POST"])
    def authorize(self):
        """ Route """
        #
        # TODO: bruteforce/csrf protections
        #
        target_token = flask.request.form.get("target", "")
        login = flask.request.form.get("login", "")
        password = flask.request.form.get("password", "")
        #
        for user in self.descriptor.config.get("users", []):
            if user["login"] == login and user["password"] == password:
                auth_ok = True
                auth_exp = datetime.datetime.now()+datetime.timedelta(seconds=86400)
                #
                auth_name = user["login"]
                auth_attributes = user.get("attributes", {})
                #
                auth_sessionindex = auth.get_auth_reference()
                if isinstance(auth_sessionindex, bytes):
                    auth_sessionindex = auth_sessionindex.decode()
                #
                try:
                    auth_user_id = \
                        self.context.rpc_manager.call.auth_get_user_from_provider(
                            auth_name
                        )["id"]
                except:  # pylint: disable=W0702
                    auth_user_id = None
                #
                auth_ctx = auth.get_auth_context()
                auth_ctx["done"] = auth_ok
                auth_ctx["error"] = ""
                auth_ctx["expiration"] = auth_exp
                auth_ctx["provider"] = "form"
                auth_ctx["provider_attr"]["nameid"] = auth_name
                auth_ctx["provider_attr"]["attributes"] = auth_attributes
                auth_ctx["provider_attr"]["sessionindex"] = auth_sessionindex
                auth_ctx["user_id"] = auth_user_id
                auth.set_auth_context(auth_ctx)
                #
                return auth.access_success_redirect(target_token)
        #
        return flask.redirect(
            flask.url_for("auth_form.login", error="true")
        )

    @web.route("/logout")
    def logout(self):
        """ Logout """
        target_token = flask.request.args.get("target_to", "")
        return auth.logout_success_redirect(target_token)
