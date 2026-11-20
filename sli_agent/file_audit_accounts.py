# SPDX-License-Identifier: Apache-2.0
"""Local user/service classification; lookup failures never become user activity."""


class UserAccountFilter:
    """Refresh configured service identities once per bounded collection batch."""

    def __init__(self):
        self.services = None
        self.accounts = {}

    def __call__(self, sid):
        import win32security
        import win32service

        if self.services is None:
            services = set()
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            try:
                for name, _display, _status in win32service.EnumServicesStatus(
                        scm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL):
                    handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
                    try:
                        account = win32service.QueryServiceConfig(handle)[7]
                        # LocalSystem is a native service alias, not an account name.
                        if account.casefold() == "localsystem":
                            services.add("S-1-5-18")
                        else:
                            resolved, _, _ = win32security.LookupAccountName(None, account)
                            services.add(win32security.ConvertSidToStringSid(resolved))
                    finally:
                        win32service.CloseServiceHandle(handle)
            finally:
                win32service.CloseServiceHandle(scm)
            self.services = services
        if sid not in self.accounts:
            name, _, kind = win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid(sid))
            self.accounts[sid] = kind == win32security.SidTypeUser and not name.endswith("$") and sid not in self.services
        return self.accounts[sid]
