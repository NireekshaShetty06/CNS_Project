import io
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import app as web
from analyzer import analyze, validate_url, public_addresses, inspect_certificate

GOOD={'status':'verified','verified':True,'hostname_match':True,'chain_verified':True,'days_remaining':90}
class ProjectTests(unittest.TestCase):
    def scan(self,url,cert=GOOD):
        with patch('analyzer.public_addresses',return_value=['93.184.216.34']),patch('analyzer.inspect_certificate',return_value=cert): return analyze(url)
    def test_normal_url(self):
        r=self.scan('example.com'); self.assertEqual(r['category'],'likely_legitimate');self.assertEqual(r['score'],0)
    def test_deceptive_url(self):
        r=self.scan('http://bank.com@secure-login-verify-account.example.com/'+'x'*220)
        self.assertEqual(r['category'],'high_risk');self.assertLessEqual(r['score'],100)
    def test_missing_tls_incomplete(self):
        r=self.scan('https://example.com',{'status':'unavailable','error':'timeout'});self.assertTrue(r['incomplete']);self.assertEqual(r['category'],'suspicious')
    def test_invalid_tls(self):
        r=self.scan('https://example.com',{'status':'verification_failed','error':'expired'});self.assertEqual(r['score'],40)
    def test_bad_input(self):
        for v in ['',None,'javascript:alert(1)','https://bad host.com','https://example.com:22','https://example.com\\@x.com']:
            with self.subTest(v=v),self.assertRaises(ValueError):validate_url(v)
    def test_network_boundary(self):
        for addr in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','192.168.1.1']:
            with patch('socket.getaddrinfo',return_value=[(2,1,6,'',(addr,443))]),self.assertRaises(ValueError):public_addresses('example.com',443)
    def test_mixed_dns_rejected(self):
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443)),(2,1,6,'',('127.0.0.1',443))]),self.assertRaises(ValueError):public_addresses('example.com',443)
    def test_certificate_success(self):
        context=MagicMock(); conn=context.wrap_socket.return_value.__enter__.return_value
        conn.getpeercert.return_value={'notBefore':'Jan  1 00:00:00 2026 GMT','notAfter':'Jan  1 00:00:00 2030 GMT','issuer':((('commonName','Test CA'),),),'subjectAltName':(('DNS','example.com'),)}
        conn.version.return_value='TLSv1.3'
        with patch('ssl.create_default_context',return_value=context),patch('socket.create_connection'):
            r=inspect_certificate('example.com',['8.8.8.8']);self.assertTrue(r['verified']);self.assertTrue(r['hostname_match']);context.wrap_socket.assert_called_once()
    def test_certificate_failure(self):
        context=MagicMock();error=ssl.SSLCertVerificationError('failed');error.verify_code=62;error.verify_message='Hostname mismatch'
        context.wrap_socket.side_effect=error
        with patch('ssl.create_default_context',return_value=context),patch('socket.create_connection'):
            r=inspect_certificate('example.com',['8.8.8.8']);self.assertFalse(r['hostname_match']);self.assertEqual(r['status'],'verification_failed')
    def test_api_history(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(web,'DB',Path(tmp)/'test.sqlite3'),patch.object(web,'analyze',return_value=self.scan('https://example.com')):
            c=web.app.test_client()
            response=c.get('/');self.assertEqual(response.status_code,200);response.close()
            self.assertEqual(c.post('/api/analyze',json={'url':'https://example.com'}).status_code,200)
            self.assertEqual(len(c.get('/api/history').json),1);c.delete('/api/history');self.assertEqual(c.get('/api/history').json,[])
    def test_metrics(self):
        c=web.app.test_client();data=b'label,prediction\nphishing,high_risk\nphishing,likely_legitimate\nlegitimate,suspicious\nlegitimate,likely_legitimate\n'
        r=c.post('/api/evaluate',data={'file':(io.BytesIO(data),'test.csv')}).json
        self.assertEqual([r[k] for k in ['tp','tn','fp','fn']],[1,1,1,1]);self.assertEqual(r['f1'],.5)
    def test_invalid_csv(self):
        c=web.app.test_client();self.assertEqual(c.post('/api/evaluate',data={'file':(io.BytesIO(b'bad,columns\na,b'),'x.csv')}).status_code,400)
if __name__=='__main__':unittest.main()
