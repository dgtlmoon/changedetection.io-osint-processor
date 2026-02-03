"""
SMTP/Email Server Fingerprinting Step
Connects to SMTP service to extract server banner, capabilities, and security features
"""

import asyncio
import socket
from loguru import logger


async def scan_smtp(hostname, ports=[25, 587, 465], timeout=5, watch_uuid=None, update_signal=None):
    """
    Perform SMTP server fingerprinting on multiple ports

    Args:
        hostname: Target hostname or IP address
        ports: List of SMTP ports to check (default: [25, 587, 465])
        timeout: Connection timeout in seconds
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: SMTP fingerprint data for all ports
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="SMTP")

    async def smtp_fingerprint_port(port):
        """Fingerprint SMTP on a specific port"""
        result = {
            'port': port,
            'port_open': False,
            'banner': None,
            'server': None,
            'ehlo_response': [],
            'capabilities': [],
            'supports_starttls': False,
            'supports_auth': False,
            'auth_methods': [],
            'supports_pipelining': False,
            'supports_smtputf8': False,
            'supports_chunking': False,
            'supports_8bitmime': False,
            'max_message_size': None,
            'is_ssl_wrapped': port == 465,  # Port 465 is implicit TLS
            'error': None
        }

        try:
            # Connect to SMTP port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port),
                timeout=timeout
            )

            result['port_open'] = True

            try:
                # Read SMTP banner (220 response)
                banner_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                banner = banner_line.decode('utf-8', errors='ignore').strip()
                result['banner'] = banner

                # Parse server from banner (format: "220 hostname ESMTP server-software")
                if ' ESMTP ' in banner or ' SMTP ' in banner:
                    parts = banner.split(' ', 3)
                    if len(parts) >= 3:
                        result['server'] = parts[2] if len(parts) == 3 else parts[3]

                logger.debug(f"SMTP banner (port {port}): {banner}")

                # Send EHLO command to get capabilities
                ehlo_cmd = f"EHLO changedetection.io\r\n"
                writer.write(ehlo_cmd.encode())
                await writer.drain()

                # Read EHLO response (multiple lines, ends with code without -)
                ehlo_lines = []
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    ehlo_lines.append(line_str)

                    # SMTP multiline responses: "250-" continues, "250 " ends
                    if line_str and len(line_str) >= 4 and line_str[3] == ' ':
                        break
                    if len(ehlo_lines) > 50:  # Safety limit
                        break

                result['ehlo_response'] = ehlo_lines

                # Parse capabilities from EHLO response
                for line in ehlo_lines:
                    # Skip the first line (usually just "250-hostname")
                    if not line.startswith('250'):
                        continue

                    # Remove "250-" or "250 " prefix
                    capability = line[4:].strip() if len(line) > 4 else ''

                    if capability:
                        result['capabilities'].append(capability)

                        # Parse specific capabilities
                        cap_upper = capability.upper()

                        if cap_upper.startswith('STARTTLS'):
                            result['supports_starttls'] = True
                        elif cap_upper.startswith('AUTH'):
                            result['supports_auth'] = True
                            # Parse auth methods (format: "AUTH LOGIN PLAIN CRAM-MD5")
                            auth_parts = capability.split()
                            if len(auth_parts) > 1:
                                result['auth_methods'] = auth_parts[1:]
                        elif cap_upper.startswith('PIPELINING'):
                            result['supports_pipelining'] = True
                        elif cap_upper.startswith('SMTPUTF8'):
                            result['supports_smtputf8'] = True
                        elif cap_upper.startswith('CHUNKING'):
                            result['supports_chunking'] = True
                        elif cap_upper.startswith('8BITMIME'):
                            result['supports_8bitmime'] = True
                        elif cap_upper.startswith('SIZE'):
                            # Parse max message size (format: "SIZE 52428800")
                            size_parts = capability.split()
                            if len(size_parts) > 1:
                                try:
                                    result['max_message_size'] = int(size_parts[1])
                                except ValueError:
                                    pass

                # Send QUIT command
                writer.write(b"QUIT\r\n")
                await writer.drain()

            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            result['error'] = f"Connection timeout (port {port})"
            logger.debug(f"SMTP connection timeout: {hostname}:{port}")
        except ConnectionRefusedError:
            result['error'] = f"Connection refused (port {port} closed or filtered)"
        except socket.gaierror as e:
            result['error'] = f"DNS resolution failed: {e}"
        except Exception as e:
            result['error'] = f"Connection error: {str(e)}"
            logger.debug(f"SMTP fingerprint error on port {port}: {e}")

        return result

    # Scan all ports in parallel
    results = await asyncio.gather(*[smtp_fingerprint_port(port) for port in ports])

    return {
        'ports_scanned': ports,
        'results': results,
        'open_ports': [r['port'] for r in results if r['port_open']]
    }


def format_smtp_results(smtp_results):
    """Format SMTP fingerprint results for output"""
    lines = []
    lines.append("=== SMTP/Email Server Fingerprint ===")

    if not smtp_results:
        lines.append("No SMTP scan results")
        lines.append("")
        return '\n'.join(lines)

    if not smtp_results.get('open_ports'):
        lines.append("Status: ✗ No SMTP ports open (checked ports: {})".format(
            ', '.join(map(str, smtp_results.get('ports_scanned', [])))
        ))
        lines.append("")
        return '\n'.join(lines)

    # Summary
    open_ports = smtp_results.get('open_ports', [])
    lines.append(f"Status: ✓ SMTP service detected on {len(open_ports)} port(s): {', '.join(map(str, open_ports))}")
    lines.append("")

    # Detail each port
    for result in smtp_results.get('results', []):
        if not result.get('port_open'):
            continue

        port = result['port']
        lines.append(f"--- Port {port} ---")

        # Port type description
        if port == 25:
            lines.append("  Port Type: SMTP (standard mail transfer)")
        elif port == 587:
            lines.append("  Port Type: Submission (client mail submission, usually requires auth)")
        elif port == 465:
            lines.append("  Port Type: SMTPS (implicit TLS/SSL)")
        else:
            lines.append(f"  Port Type: Custom SMTP port")

        # Banner and server
        if result.get('banner'):
            lines.append(f"  Banner: {result['banner']}")
        if result.get('server'):
            lines.append(f"  Server Software: {result['server']}")

            # Identify server type
            server = result['server'].lower()
            if 'postfix' in server:
                lines.append("    Server Type: Postfix (popular open-source MTA)")
            elif 'exim' in server:
                lines.append("    Server Type: Exim (flexible Unix MTA)")
            elif 'sendmail' in server:
                lines.append("    Server Type: Sendmail (classic Unix MTA)")
            elif 'microsoft' in server or 'exchange' in server:
                lines.append("    Server Type: Microsoft Exchange")
            elif 'zimbra' in server:
                lines.append("    Server Type: Zimbra Collaboration Suite")
            elif 'qmail' in server:
                lines.append("    Server Type: Qmail (secure MTA)")
            elif 'haraka' in server:
                lines.append("    Server Type: Haraka (modern Node.js MTA)")

        # Capabilities
        if result.get('capabilities'):
            lines.append(f"  Capabilities: {len(result['capabilities'])} feature(s)")

        # Security features
        lines.append("  Security Features:")
        has_security = False

        if result.get('supports_starttls'):
            lines.append("    ✓ STARTTLS - Opportunistic TLS encryption supported")
            has_security = True
        elif not result.get('is_ssl_wrapped'):
            lines.append("    ✗ STARTTLS - NOT supported (unencrypted connection)")

        if result.get('is_ssl_wrapped'):
            lines.append("    ✓ Implicit TLS - Connection is encrypted from start")
            has_security = True

        if result.get('supports_auth'):
            lines.append(f"    ✓ Authentication required")
            if result.get('auth_methods'):
                auth_methods = result['auth_methods']
                lines.append(f"      Methods: {', '.join(auth_methods)}")

                # Security assessment of auth methods
                for method in auth_methods:
                    method_upper = method.upper()
                    if method_upper == 'PLAIN':
                        if result.get('supports_starttls') or result.get('is_ssl_wrapped'):
                            lines.append(f"        {method}: ⚠ Plaintext auth (safe over TLS)")
                        else:
                            lines.append(f"        {method}: ✗ INSECURE (plaintext over unencrypted connection)")
                    elif method_upper == 'LOGIN':
                        if result.get('supports_starttls') or result.get('is_ssl_wrapped'):
                            lines.append(f"        {method}: ⚠ Base64 encoded (safe over TLS)")
                        else:
                            lines.append(f"        {method}: ✗ INSECURE (base64 over unencrypted connection)")
                    elif method_upper in ['CRAM-MD5', 'DIGEST-MD5']:
                        lines.append(f"        {method}: ✓ Challenge-response (resistant to replay)")
                    elif method_upper in ['SCRAM-SHA-1', 'SCRAM-SHA-256']:
                        lines.append(f"        {method}: ✓ Modern SCRAM authentication")
                    elif method_upper == 'XOAUTH2':
                        lines.append(f"        {method}: ✓ OAuth 2.0 token authentication")
        else:
            if port == 25:
                lines.append("    ⚠ No authentication (open relay risk if not restricted)")
            else:
                lines.append("    ✗ No authentication advertised")

        if not has_security and not result.get('supports_starttls') and not result.get('is_ssl_wrapped'):
            lines.append("    ✗ No encryption - traffic is sent in plaintext")

        # Extended features
        extended_features = []
        if result.get('supports_pipelining'):
            extended_features.append("PIPELINING (performance)")
        if result.get('supports_8bitmime'):
            extended_features.append("8BITMIME (international characters)")
        if result.get('supports_smtputf8'):
            extended_features.append("SMTPUTF8 (international email addresses)")
        if result.get('supports_chunking'):
            extended_features.append("CHUNKING (efficient large messages)")

        if extended_features:
            lines.append("  Extended Features:")
            for feature in extended_features:
                lines.append(f"    • {feature}")

        # Message size limit
        if result.get('max_message_size'):
            size_mb = result['max_message_size'] / (1024 * 1024)
            lines.append(f"  Max Message Size: {size_mb:.1f} MB ({result['max_message_size']:,} bytes)")

        lines.append("")

    # Overall security assessment
    lines.append("Overall Email Security Assessment:")

    has_tls_port = any(r.get('supports_starttls') or r.get('is_ssl_wrapped') for r in smtp_results.get('results', []) if r.get('port_open'))
    has_auth = any(r.get('supports_auth') for r in smtp_results.get('results', []) if r.get('port_open'))

    if has_tls_port and has_auth:
        lines.append("  ✓ Good: Encryption and authentication are available")
    elif has_tls_port:
        lines.append("  ⚠ Moderate: Encryption available but check authentication requirements")
    elif has_auth:
        lines.append("  ⚠ Weak: Authentication available but no encryption (credentials exposed)")
    else:
        lines.append("  ✗ Poor: No encryption or authentication detected")

    # Recommendations
    lines.append("")
    lines.append("Recommendations:")

    if not has_tls_port:
        lines.append("  • Enable STARTTLS on port 587 or use implicit TLS on port 465")

    if not has_auth:
        lines.append("  • Require SMTP authentication to prevent abuse")

    # Check for port 25 without restrictions
    port_25_result = next((r for r in smtp_results.get('results', []) if r.get('port') == 25 and r.get('port_open')), None)
    if port_25_result and not port_25_result.get('supports_auth'):
        lines.append("  • Port 25 should only accept mail from trusted sources (not open relay)")

    if has_tls_port and has_auth:
        lines.append("  • Security looks good - continue monitoring for configuration changes")

    lines.append("")
    return '\n'.join(lines)
