def patch_pymysql_for_gbase():
    from pymysql import connections
    from pymysql.connections import err, _auth

    def _new_process_auth(self, plugin_name, auth_packet):
        handler = self._get_auth_plugin_handler(plugin_name)
        if handler:
            try:
                return handler.authenticate(auth_packet)
            except AttributeError:
                if plugin_name != b'dialog':
                    raise err.OperationalError(2059, "Authentication plugin '%s'"
                                                     " not loaded: - %r missing authenticate method" % (
                                               plugin_name, type(handler)))
        if plugin_name == b"caching_sha2_password":
            return _auth.caching_sha2_password_auth(self, auth_packet)
        elif plugin_name == b"sha256_password":
            return _auth.sha256_password_auth(self, auth_packet)
        elif plugin_name == b"mysql_native_password":
            data = _auth.scramble_native_password(self.password, auth_packet.read_all())
        elif plugin_name == b"gbase_native_password": # added this shit, the same as mysql
            data = _auth.scramble_native_password(self.password, auth_packet.read_all())
        elif plugin_name == b"mysql_old_password":
            data = _auth.scramble_old_password(self.password, auth_packet.read_all()) + b'\0'
        elif plugin_name == b"mysql_clear_password":
            # https://dev.mysql.com/doc/internals/en/clear-text-authentication.html
            data = self.password + b'\0'
        elif plugin_name == b"dialog":
            pkt = auth_packet
            while True:
                flag = pkt.read_uint8()
                echo = (flag & 0x06) == 0x02
                last = (flag & 0x01) == 0x01
                prompt = pkt.read_all()

                if prompt == b"Password: ":
                    self.write_packet(self.password + b'\0')
                elif handler:
                    resp = 'no response - TypeError within plugin.prompt method'
                    try:
                        resp = handler.prompt(echo, prompt)
                        self.write_packet(resp + b'\0')
                    except AttributeError:
                        raise err.OperationalError(2059, "Authentication plugin '%s'" \
                                                         " not loaded: - %r missing prompt method" % (
                                                   plugin_name, handler))
                    except TypeError:
                        raise err.OperationalError(2061, "Authentication plugin '%s'" \
                                                         " %r didn't respond with string. Returned '%r' to prompt %r" % (
                                                   plugin_name, handler, resp, prompt))
                else:
                    raise err.OperationalError(2059, "Authentication plugin '%s' (%r) not configured" % (
                    plugin_name, handler))
                pkt = self._read_packet()
                pkt.check_error()
                if pkt.is_ok_packet() or last:
                    break
            return pkt
        else:
            raise err.OperationalError(2059, "Authentication plugin '%s' not configured" % plugin_name)

        self.write_packet(data)
        pkt = self._read_packet()
        pkt.check_error()
        return pkt
    connections.Connection._process_auth = _new_process_auth
