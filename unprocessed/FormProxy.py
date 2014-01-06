############################################################################
##
## Copyright (c) 2008, Árpád Magosányi
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
## $Id$
##
## Author  : Mag
## Auditor : 
## Last audited version:
## Notes:
##
############################################################################

"""<module maturity="stable">
<description>
<para>
This module contains the code which does input validation for applications using HTTP forms. The FormProxy is a normal HTTP proxy, with added code to check forms.
</para>
<para>
HTTP forms can be submitted in three ways:
<itemizedlist>
	<listitem><para><emphasis>GET method</emphasis> -- the form data is submitted in the URL</para></listitem>
	<listitem><para><emphasis>URL encoded POST</emphasis> -- the form data is submitted in the body of a POST request with the application/x-www-form-urlencoded mime-type</para></listitem>
	<listitem><para><emphasis>multipart POST</emphasis> -- the form data is submitted in the body of a POST request with the multipart/form-data mime-type. This is used for file controls.</para><listitem>
</itemizedlist>
The FormProxy hides these details. The HTTP proxy is configured to extract the form controls in all three cases and enforce the policy defined with the help of hashes.
</para>
<para>
The policy is defined by a hash, indexed by the form url and the form name. The hash value is a function with three parameters: proxy,name,value. Proxy is the proxy instance (self), name the form control name, value is its value. If the value is ok for the control, the tuple (name,value) should be returned. If the value is not OK, False should be returned. The proxy will forward the value returned by the function. This way the form value (or even name) can be normalized.
</para>
<para>
File controls have a similar policy, but with more possibilities. The file policy hash is indexed by a 4-tuple: (request_url,name,type,subtype). The type and subtipe are the relevant parts of the file's content-type. The checker function receives 5 arguments: proxy and name is the same as with the "normal" policy. Value contains the content of the uploaded file. Content_type is the content type, file_name is the file name given at upload.
</para>
<para>
	Relevant standards:
	<itemizedlist>
		<listitem><para>HTML 4.01 specification http://www.w3.org/TR/html401/interact/forms.html</para></listitem>
		<listitem><para>RFC 1738: Uniform Resource Locators</para></listitem>
		<listitem><para>RFC 2388: Returning Values from Forms:  multipart/form-data</para></listitem>
		<listitem><para>RFC 2045, RFC 2046: Multipurpose Internet Mail Extensions</para></listitem>
	</itemizedlist>
</para>
<para>
Here is an example FormProxy class. You can see that some items are the same as a normal HTTP proxy configuration. The difference is the policy definition and the call of set_form_policy method.
</para>
<literallayout>
class MyFormProxy(FormProxy):
	def config(self):
		self.transparent_mode = TRUE
		# self.parent_proxy = "proxy.site.net"
		# self.parent_proxy_port = 3128
		self.timeout = 1000
		# self.max_keepalive_requests = 10
		policy={
			("http://mag.webhome.hu/test/form","family"): CheckString(self,0,30),
			("*","gender"): CheckString(self,0,4),
			("*","thename"): CheckString(self,0,4),
			("*","*"): CheckTrue(),
		}
		filepolicy={
			("*","*","*","*"): CheckFileTrue(),
		}
		self.set_form_policy(policy,filepolicy,silent_drop=0,drop_empty=0,one_blob=1)
</literallayout
<para><warning>
You should not use request['GET'], request_stack["POST"] and request_headers["CONTENT-TYPE"] in the Formproxy configuration, as these are overwritten in the set_form_policy call.
</warning></para>
	
</description>
<metainfo>
<enums></enums>
<actiontuples></actiontuples>
<constants></constants>
</metainfo>
</module>
"""
import urllib
from Zorp import Zorp,Http,AnyPy,Stream
import re

AbortProxyException="Abort Proxy"
CRLF="\r\n"

class FormChecker:
	"""
	<class maturity="stable" abstract="no">
		<summary>
			Class to do syntax check on form data
		</summary>
		<description>
			This class encapsulates the syntax checks which are used in multiple form types (at least two of GET, URL encoded POST and multipart POST).
			It is designed to be used with the FormChecker proxy. This class handles syntax checking and policy, FormChecker handles the protocol-specific part.
		</description>
		<metainfo>
			<attributes>
			<attribute maturity="stable" internal="yes">
				<name>policy</name>
				<type>hash</type>
				<description>
					The hash describing the policy for control value check.
					The index should be a tuple of two strings: url and control name.
					The url and/or the control name can be "*" which means any.
					The value is a function with three parameters: proxy,name,value
					<ul>
					<li>proxy is the proxy instance where it is called from (proxy.session.session_id is used)</li>
					<li>name is the control name</li>
					<li>value is the control's value</li>
					</ul>
					The function shall return a tuple of the same parameters normalized, or False if there is a policy violation.
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>file_policy</name>
				<type>hash</type>
				<description>
					The hash describing the policy for file control check.
					The index should be a tuple of four strings:(request_url,name,type,subtype).
					<ul>
						<li>request_url is the request url</li>
						<li>name is the control name</li>
						<li>type is the type (first tag, before '/') of the content type</li>
						<li>subtype is the subtype (second tag, after '/') of the content type</li>
					</ul>
					Any string can be "*" which means any.
					The value is a function with five parameters: proxy,name,value,content_type,file_name
					<ul>
					<li>proxy is the proxy instance where it is called from (proxy.session.session_id is used)</li>
					<li>name is the control name</li>
					<li>value is the file content</li>
					<li>content_type is the file's content-type</li>
					<li>file_name is the file name given</li>
					</ul>
					The function shall return a tuple of the same parameters normalized, or False if there is a policy violation.
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>drop_empty</name>
				<type>boolean</type>
				<description>
					Whether to drop controls with empty value.
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>silent_drop</name>
				<type>boolean</type>
				<description>
					Whether to drop controls which violate policy.
					If True, the violating controls are dropped, but the request is not.
					If False, the whole request is dropped when a contol violates the policy.
					<warning>For secure functionality one_blob should also be True if silent_drop is False.</warning>
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>one_blob</name>
				<type>boolean</type>
				<description>
					Shall we process all controls of a multipart request in one run, or pass them after they have been validated and normalized.
					If True, the proxy sends a multipart request with one write. This may go with big memory consumption.
					If False, the proxy sends each request after it is processed. As rejecting the request is only possible before the first control is passed, some (checked, validated) part of the request may reach the server even in case of policy violation. See also silent_drop.
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>filenamere</name>
				<type>string</type>
				<description>
					The regular expression which the file names of file controls should match with.
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>default_filename</name>
				<type>string</type>
				<description>
					The default filename: it will be used if the filename does not adhere to filenamere.
					If it is None, then a bad filename is a policy violation.
				</description>
			</attribute>
			<attribute maturity="stable" internal="yes">
				<name>session</name>
				<type>Session instance</type>
				<description>
					The session. It is used for logging purposes.
				</description>
			</attribute>
			</attributes>
		</metainfo>
	</class>
	"""

	def __init__(self,session,policy,file_policy,drop_empty=1,silent_drop=0,one_blob=0,filename_pattern="^[a-zA-Z._\.]*",default_filename=None):
		"""
		<method>
		<metainfo>
			<summary>Initializes a FormChecker instance</summary>
			<attributes>
			<attribute maturity="stable">
				<name>session</name>
				<type>Session instance</type>
				<description>
					The session. It is used for logging purposes.
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>policy</name>
				<type>hash</type>
				<description>
					The hash describing the policy for control value check.
					The index should be a tuple of two strings: url and control name.
					The url and/or the control name can be "*" which means any.
					The value is a function with three parameters: proxy,name,value
					<ul>
					<li>proxy is the proxy instance where it is called from (proxy.session.session_id is used)</li>
					<li>name is the control name</li>
					<li>value is the control's value</li>
					</ul>
					The function shall return a tuple of the same parameters normalized, or False if there is a policy violation.
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>file_policy</name>
				<type>hash</type>
				<description>
					The hash describing the policy for file control check.
					The index should be a tuple of four strings:(request_url,name,type,subtype).
					<ul>
						<li>request_url is the request url</li>
						<li>name is the control name</li>
						<li>type is the type (first tag, before '/') of the content type</li>
						<li>subtype is the subtype (second tag, after '/') of the content type</li>
					</ul>
					Any string can be "*" which means any.
					The value is a function with five parameters: proxy,name,value,content_type,file_name
					<ul>
					<li>proxy is the proxy instance where it is called from (proxy.session.session_id is used)</li>
					<li>name is the control name</li>
					<li>value is the file content</li>
					<li>content_type is the file's content-type</li>
					<li>file_name is the file name given</li>
					</ul>
					The function shall return a tuple of the same parameters normalized, or False if there is a policy violation.
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>drop_empty</name>
				<type>boolean</type>
				<description>
					Whether to drop controls with empty value.
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>silent_drop</name>
				<type>boolean</type>
				<description>
					Whether to drop controls which violate policy.
					If True, the violating controls are dropped, but the request is not.
					If False, the whole request is dropped when a contol violates the policy.
					<warning>For secure functionality one_blob should also be True if silent_drop is False.</warning>
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>one_blob</name>
				<type>boolean</type>
				<description>
					Shall we process all controls of a multipart request in one run, or pass them after they have been validated and normalized.
					If True, the proxy sends a multipart request with one write. This may go with big memory consumption.
					If False, the proxy sends each request after it is processed. As rejecting the request is only possible before the first control is passed, some (checked, validated) part of the request may reach the server even in case of policy violation. See also silent_drop.
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>filename_pattern</name>
				<type>string</type>
				<description>
					The regular expression which the file names of file controls should match with.
				</description>
			</attribute>
			<attribute maturity="stable">
				<name>default_filename</name>
				<type>string</type>
				<description>
					The default filename to which a filename violating the policy is changed. If None, the request is denied.
				</description>
			</attribute>
			</attributes>
			<description><para>
			Initializes instance attributes.
			</para></description>
		</metainfo>
		</method>
		"""
		self.policy=policy
		self.file_policy=file_policy
		self.drop_empty=drop_empty
		self.silent_drop=silent_drop
		self.one_blob=one_blob
		self.filenamere=re.compile(filename_pattern)
		self.default_filename=default_filename
		self.controlnamere=re.compile("^[A-Za-z][A-Za-z0-9-_:\.]*$")
		self.contenttypere=re.compile("^[A-Za-z][A-Za-z0-9-_:\./]*$")
		self.session=session
	def urlencodedcheck(self,request_url,args=""):
		"""
			<method internal="yes">
				<summary>
					This method checks an URL-encoded form data against policy.
				</summary
				<description><para>
					The args parameter contains the form data, name=value pairs separated by '&amp;', and special characters encoded in %xx form.
					The (name,value) pairs are identified, the value is urldecoded, and the pairs are checked with checkOneArg.
					If a value is empty and the drop_empty attribute of the form policy is true, the pair is dropped, and no check performed for it.
					If a check fails, and the silent_drop form policy attribute is true, the pair is dropped.
					If all went well, the remaining form data is reconstructed, the values are url encoded and the normalized form data is returned.
					If a check fails, and the silent_drop form policy attribute is not true, False is returned.
				</para></description>
				<metainfo> <arguments>
					<argument maturity="stable">
						<name>self</name>
						<type>FormChecker instance</type>
						<description>The class instance</description>
					</argument>
					<argument maturity="stable">
						<name>request_url</name>
						<type>string</type>
						<description>the URL of the request</description>
					</argument>
					<argument maturity="stable">
						<name>args</name>
						<type>string</type>
						<description>URL encoded form data</description>
					</argument>
				</arguments> </metainfo>
			</method>
		"""
		ret=[]
		for arg in args.split("&"):
			nv = arg.split("=")
			if len(nv) != 2:
				if self.silent_drop:
					continue
				else:
					return False
			(name,value) = nv
			if not self.controlnamere.match(name):
				Zorp.log("form.policy", 3, "%s: DENY: invalid control name" % (self.session.session_id))
				return False
			value=urllib.unquote_plus(value)
			Zorp.log("form.info",1, "%s: checking (%s,%s)" % (self.session.session_id, name, value.encode("string_escape")))
			if value == "" and self.drop_empty:
				Zorp.log("form.policy",2, "%s: dropping empty arg (%s) " % (self.session.session_id, name.encode("string_escape")))
				pass
			else:
				r=self.checkOneArg(request_url,name,value)
				if r == False and not self.silent_drop:
					return False
				if r:
					(name,value)=r
					value=urllib.quote_plus(value)
					ret.append("%s=%s"%(name,value))
		return "&".join(ret)

	def checkOneArg(self,request_url,name,value):
		"""
			<method internal="yes">
				<summary>
					This method checks one form control.
				</summary
				<description><para>
					The policy is searched for a checker function based on request_url and name. If there is such a checker, then it is called with the name and the value, and its return value is returned. If no checker, then 0 (deny) is returned.
				</para></description>
				<metainfo> <arguments>
					<argument maturity="stable">
						<name>self</name>
						<type>FormChecker instance</type>
						<description>The class instance</description>
					</argument>
					<argument maturity="stable">
						<name>request_url</name>
						<type>string</type>
						<description>the URL of the request</description>
					</argument>
					<argument maturity="stable">
						<name>name</name>
						<type>string</type>
						<description>the name of the control</description>
					</argument>
					<argument maturity="stable">
						<name>value</name>
						<type>string</type>
						<description>the value of the control</description>
					</argument>
				</arguments> </metainfo>
			</method>
		"""
		for searcher in [(request_url,name),("*",name),("request_url",name),("*","*")]:
			if self.policy.has_key(searcher):
				Zorp.log("form.info",2, "%s: got checker for %s " % (self.session.session_id, searcher))
				return self.policy[searcher](self,name,value)
		else:
			Zorp.log("form.policy",2, "%s: no default checker, giving up " % (self.session.session_id))
			return 0

	def checkFileArg(self,request_url,name,data,content_type,filename):
		"""
			<method internal="yes">
				<summary>
					This method checks one file form control.
				</summary
				<description><para>
					The file_policy is searched for a checker function based on request_url,name,type and subtype of content-type. If there is such a checker, then it is called with the name, data, content-type and filename, and its return value is returned. If no checker, then 0 (deny) is returned.
				</para></description>
				<metainfo> <arguments>
					<argument maturity="stable">
						<name>self</name>
						<type>FormChecker instance</type>
						<description>The class instance</description>
					</argument>
					<argument maturity="stable">
						<name>request_url</name>
						<type>string</type>
						<description>the URL of the request</description>
					</argument>
					<argument maturity="stable">
						<name>name</name>
						<type>string</type>
						<description>the name of the control</description>
					</argument>
					<argument maturity="stable">
						<name>data</name>
						<type>string</type>
						<description>the value of the control</description>
					</argument>
					<argument maturity="stable">
						<name>content-type</name>
						<type>string</type>
						<description>content-type of the control</description>
					</argument>
					<argument maturity="stable">
						<name>filename</name>
						<type>string</type>
						<description>the filename of the control</description>
					</argument>
				</arguments> </metainfo>
			</method>
		"""
		ts=content_type.split("/")
		if len(ts) != 2:
			Zorp.log("form.policy",2, "%s: invalid content-type %s " % (self.session.session_id, content_type.encode("string_escape")))
			return 0
		(type,subtype)=ts
		for searcher in [(request_url,name,type,subtype),
				 ("*",name,type,subtype),
				 (request_url,"*",type,subtype),
				 (request_url,name,"*",subtype),
				 (request_url,name,type,"*"),
				 ("*","*",type,subtype),
				 ("*",name,"*",subtype),
				 ("*",name,type,"*"),
				 (request_url,"*","*",subtype),
				 (request_url,"*",type,"*"),
				 (request_url,name,"*","*"),
				 ("*","*","*",subtype),
				 ("*","*",type,"*"),
				 ("*",name,"*","*"),
				 (request_url,"*","*","*"),
				 ("*","*","*","*")]:
			if self.file_policy.has_key(searcher):
				Zorp.log("form.info",2, "%s: got file checker for %s " % (self.session.session_id, searcher))
				return self.file_policy[searcher](self,name,data,content_type,filename)
		else:
			Zorp.log("form.policy",2, "%s: no default file checker, giving up " % (self.session.session_id))
			return 0
		
class CheckFalse:
	"""
		<class maturity="stable" abstract="no">
			<summary>Class to be used in the policy for policy violations based on control url/name</summary>
			<description><para>
				A class instance is callable with 1+3 arguments, and returns False when called.
			</para></description>
		</class>
	"""
	def __call__(self,proxy,name,value):
		Zorp.log("form.info",3, "%s: checking (%s,%s) with CheckFalse" % (proxy.session.session_id, name, value.encode("string_escape")))
		return False

class CheckTrue:
	"""
		<class maturity="stable" abstract="no">
			<summary>Class to be used in the policy to accept a control based on url/name</summary>
			<description><para>
				A class instance is callable with 1+3 arguments, and returns a (name,value) tuple when called.
			</para></description>
		</class>
	"""
	def __call__(self,proxy,name,value):
		Zorp.log("form.info",3, "%s: checking (%s,%s) with CheckTrue" % (proxy.session.session_id, name, value.encode("string_escape")))
		return (name,value)

class CheckString:
	"""
		<class maturity="stable" abstract="no">
			<summary>Class to be used in the policy to check string against a regular expression and for length</summary>
			<description><para>
				The class instance is initialized with minimal length, maximal length and regular expression, and callable with proxy,name and value.
				TWhen called, the value is checked against the regexp and the length constraints.
			</para></description>
		</class>
	"""
	def __init__(self,proxy,minlen=0,maxlen=30,regex=None):
		"""
			<method>
				<summary>Initializes the CheckString instance</summary>
				<metainfo><attributes>
					<attribute>
						<name>self</name>
						<type>CheckString instance</type>
						<description>
							This instance.
						</description>
					</attribute>
					<attribute>
						<name>proxy</name>
						<type>Proxy instance</type>
						<description>
							The proxy the constructor is called from.
						</description>
					</attribute>
					<attribute>
						<name>minlen</name>
						<type>int</type>
						<description>
							minimum string length
						</description>
					</attribute>
					<attribute>
						<name>maxlen</name>
						<type>int</type>
						<description>
							maximum string length
						</description>
					</attribute>
					<attribute>
						<name>regex</name>
						<type>string</type>
						<description>
							The regular expression the control value should adhere to.
						</description>
					</attribute>
				</attributes></metainfo>
				<description><para>
					Sets instance attributes with the arguments. If there is a regex, it is compiled before.
				</para></description>
			</method>
		"""
		self.maxlen=maxlen
		self.minlen=minlen
		self.re=regex
		if regex:
			regex=re.compile(regex)
		self.regex = regex

	def __call__(self,proxy,name,value):
		"""
			<method>
				<summary>the method called when the instance is</summary>
				<metainfo><attributes>
					<attribute>
						<name>self</name>
						<type>CheckString instance</type>
						<description>
							This instance.
						</description>
					</attribute>
					<attribute>
						<name>proxy</name>
						<type>Proxy instance</type>
						<description>
							The proxy the constructor is called from.
						</description>
					</attribute>
					<attribute>
						<name>name</name>
						<type>string</type>
						<description>
							form control name
						</description>
					</attribute>
					<attribute>
						<name>value</name>
						<type>string</type>
						<description>
							form control value
						</description>
					</attribute>
				</attributes></metainfo>
				<description><para>
					The value is checked against the regular expression and length. If all okay, a (name,value) tuple is returned, else a False returned.
				</para></description>
			</method>
		"""
		Zorp.log("form.info",3, "%s: checking (%s,%s) with CheckString(%u,%u,%s)" % (proxy.session.session_id, name, value.encode("string_escape"),self.minlen,self.maxlen,self.re))
		if self.minlen <= len(value) <= self.maxlen:
			if self.regex:
				if not self.regex.search(value):
					return False
			return (name,value)
		return False

class CheckFileTrue:
	"""
		<class maturity="stable" abstract="no">
			<summary>Class to be used in the policy to accept file control</summary>
			<description><para>
				A class instance is callable with 1+5 arguments, and returns a (name,value,content_type,file_name) tuple when called.
			</para></description>
		</class>
	"""
	def __call__(self,proxy,name,value,content_type,file_name):
		Zorp.log("form.info",3, "%s: checking (%s,%s) with CheckTrue" % (proxy.session.session_id, name, value.encode("string_escape")))
		return (name,value,content_type,file_name)

class CheckFileFalse:
	"""
		<class maturity="stable" abstract="no">
			<summary>Class to be used in the policy for policy violations based on file control url/name/content_type</summary>
			<description><para>
				A class instance is callable with 1+5 arguments, and returns False when called.
			</para></description>
		</class>
	"""
	def __call__(self,proxy,name,value,content_type,file_name):
		Zorp.log("form.info",3, "%s: checking (%s,%s) with CheckTrue" % (proxy.session.session_id, name, value.encode("string_escape")))
		return Fales


class InvalidProxy(AnyPy.AnyPyProxy):
	"""
	<class maturity=stable>
		<summary>A proxy which sets a DENY verdict and raises AbortProxyException. Used to signal unknown POST encoding.</summary>
	</class>
	"""
	def proxyThread(self):
		Zorp.log("form.policy", 3, "%s: DENY: %s" % (self.session.session_id,"Unknown POST encoding"))
		self.set_verdict(AnyPy.ANYPY_DENY,"Unknown POST encoding")
		raise AbortProxyException

class MultiPartProxy(AnyPy.AnyPyProxy):
	"""
	<class maturity=stable>
		<summary>Proxy processing multipart encoded form data</summary>
		<description><para>
			This class implements a proxy to check multipart encoded form data, stackable on http request data.
			The request is split by the boundary (given in the http request headers)
			Parts are checked for the name and filename attributes of the content-disposition header, and content-type header.
			Name, data portion, and possibly filename and content-type are checked against policy (or file_policy).
			Form policy is assumed to be a FormChecker instance in the form_policy attribute of the stacking proxy.
		</para></description>
	</class>
	"""

	def __init__(self,session):
		"""
			<method>
				<summary>Constructor</summary>
				<description><para>
					Constant regular expressions are compiled.
				</para></description>
			</method>
		"""
		self.content_type_re=re.compile("(?i)coNtent-type:")
		self.content_disposition_re=re.compile("(?i)coNtent-disPosition:")
		self.file_name_re=re.compile('(?i)filename="(?P<name>.*)"')
		self.form_data_re=re.compile("(?i)form-data[ ]*$")
		self.control_name_re=re.compile('(?i)name="(?P<name>.*)"')
		AnyPy.AnyPyProxy.__init__(self,session)

	def config(self):
		"""
			<method>
				<summary>config event</summary>
				<description><para>
					The configuration parameters for the line mode stream on the client side are set.
					This is just for the example, because these are the default values.
				</para></description>
			</method>
		"""
		self.client_max_line_length=4096

	def abortProxy(self,message):
		"""
			<method>
				Policy violation happened, we set a DENY verdict with the given message and raise AbortProxyException
			</method>
		"""
		Zorp.log("form.policy", 3, "%s: DENY: %s" % (self.session.session_id,message))
		self.set_verdict(AnyPy.ANYPY_DENY,message)
		raise AbortProxyException

	def proxyThread(self):
		"""
			<method>
				<summary>The proxy thread.</summary>
				<description<para>
					Setting boundary, request URL and form policy from the stacking proxy, and call processMultiPart with our two streams.
				</para></description>
			</method>
		"""
		self.client_stream.split=True
		Zorp.log("form.info", 3, "%s: starting, boundary=%s" % (self.session.session_id, self.session.owner.proxy.boundary.encode("string_escape")))
		self.boundary="--"+self.session.owner.proxy.boundary
		self.request_url=self.session.owner.proxy.request_url
		self.form_policy = self.session.owner.proxy.form_policy
		Zorp.log("form.info", 3, "%s: oneblob=%s" % (self.session.session_id, self.form_policy.one_blob))
		self.parts=[]
		self.processMultiPart(self.client_stream,self.server_stream)

	def partReady(self,line):
		"""
			<method>
				<summary>A part is ready, boundary is reached. Now we check if everything in the part is okay.</summary>
				<description><para>
					First we check whether the boundary is in the correct place:
					<ul>
					<li>If it is the first boundary, we return, as there is no part is excepted before it.</li>
					<li>If we are in the headers, be signal policy violation.</li>
					</ul>
					Next we check and - if checked okay - reconstruct the part:
					<ul>
					<li>If the data part was empty and drop_empty is true, do nothing</li>
					<li>file control is recognized from existence of content-type</li>
					<li>checking if all required things (control name, in case of file control filename also) are exist.
					<li>values are checked with the fitting method (checkFileArg or checkOneArg) of form_policy</li>
					</ul>
					At the end we see whether this boundary was the last. If so, we set an ACCEPT verdict and end the story with AbortProxyException.
				</para></description>
			</method>
		"""
		self.client.nul_nonfatal=False
		if self.state == "start":
			self.state = "headers"
			return
		elif self.state == "headers":
			self.abortProxy("boundary in headers")
		elif self.state == "data":
			if self.data == [''] and self.form_policy.drop_empty:
				Zorp.log("form.policy",2, "%s: dropping empty arg (%s) " % (self.session.session_id, self.controlname.encode("string_escape")))
			else:
				self.data=CRLF.join(self.data)
				if self.content_type:
					if not (self.filename and self.controlname):
						self.abortProxy("content-type given and no filename or field name")
					ret = self.form_policy.checkFileArg(self.request_url,self.controlname,self.data,self.content_type,self.filename)
					if ret:
						(self.controlname,self.data,self.content_type,self.filename)=ret
						headers='Content-Disposition: form-data; name="%s"; filename="%s"'%(self.controlname,self.filename)+CRLF+\
							'Content-Type: %s'%self.content_type+CRLF
				else:
					if not self.controlname:
						self.abortProxy("no field name given")
					ret = self.form_policy.checkOneArg(self.request_url,self.controlname,self.data)
					Zorp.log("form.info", 3, "%s: check output: %s" % (self.session.session_id,ret))
					if ret:
						(self.controlname,self.data)=ret
						headers='Content-Disposition: form-data; name="%s"'%(self.controlname)+CRLF
				if ret:
					part= headers+\
						CRLF+\
						self.data
					if self.form_policy.one_blob:
						Zorp.log("form.policy", 3, "%s: appending to output:%s" % (self.session.session_id,part.encode("string_escape")))
						self.parts.append(part)
					else:
						Zorp.log("form.info", 3, "%s: writing part:%s" % (self.session.session_id,part.encode("string_escape")))
						self.server.write(self.boundary+CRLF+part)
				else:
					if not self.form_policy.silent_drop:
						self.abortProxy("invalid form field")
					else:
						Zorp.log("form.policy", 3, "%s: dropping silently" % (self.session.session_id))
		if line[len(self.boundary):] == "--":
			Zorp.log("form.policy", 3, "%s: form checked OK, forgetting anything after it" % (self.session.session_id))
			if self.form_policy.one_blob:
				self.server.write(self.boundary+CRLF+(CRLF+self.boundary+CRLF).join(self.parts)+CRLF+self.boundary+"--")
			else:
				self.server.write(self.boundary+"--")

			Zorp.log("form.policy", 3, "%s: ACCEPT: Form is processed" % (self.session.session_id))
			self.set_verdict(AnyPy.ANYPY_ACCEPT,"Form is processed")
			raise AbortProxyException

	def checkHeader(self,line):
		"""
			<method>
				<summary>Check a header</summary>
				<description><para>
					Check a line in the header. If it is empty, we change state, as we have reached data. We look only for content-disposition and content-type, all other headers are illegal. The needed data (content-type, name, filename) are extracted, if filename exists, it is checked against policy.
				</description></para>
			</method>
		"""
		if line == "":
			Zorp.log("form.info", 3, "%s: name=%s,filename=%s,content_type=%s" % (self.session.session_id, self.controlname,self.filename,self.content_type))
			self.state="data"
			if self.content_type:
				self.client.nul_nonfatal=True
		elif self.content_disposition_re.match(line): 
			args=line.split(";")
			Zorp.log("form.info", 5, "%s: args=%s" % (self.session.session_id, args))
			if not self.form_data_re.search(args[0]):
				self.abortProxy("Bad content-disposition")
			for i in args[1:]:
				t=self.file_name_re.search(i)
				if t:
					filename=t.group("name")
					if not self.form_policy.filenamere.match(filename):
						if self.form_policy.default_filename:
							filename=self.form_policy.default_filename
						else:
							self.abortProxy("invalid file name")
					self.filename=filename
				else:
					t=self.control_name_re.search(i) 
					if t:
						controlname=t.group("name")
						if self.form_policy.controlnamere.match(controlname):
							self.controlname=controlname
						else:
							self.abortProxy("invalid control name")
			if not self.controlname:
				self.abortProxy("No name in the content-disposition header")
		elif self.content_type_re.match(line):
			content_type=line.split(":")[1].strip().lower()
			if not self.form_policy.contenttypere.match(content_type):
				self.abortProxy("invalid content-type")
			self.content_type=content_type
		else:
			self.abortProxy("Unknown header")

	def processLine(self,line):
		"""
			<method>
				<summary>One line is read, and processed according to state</summary>
			</method>
		"""
		if line[:len(self.boundary)]==self.boundary:
			Zorp.log("form.info", 3, "%s: boundary detected" % (self.session.session_id))
			self.partReady(line)
			Zorp.log("form.info", 3, "%s: boundary processed" % (self.session.session_id))
			# initialization of variables for a new part
			self.state = "headers"
			self.controlname=None
			self.content_type=None
			self.filename=None
			self.data = []
		elif self.state == "start":
			self.abortProxy("Not starting with boundary")
		elif self.state == "headers":
			self.checkHeader(line)
		elif self.state == "data":
			self.data.append(line)
		else:
			raise NotImplementedError, "bad state"


	def processMultiPart(self,client,server):
		"""
			<method>
			<summary>Processing the multipart message. It is a separate method from proxythread, so client and server can be made a blob if we will now how to do it.</summary>
			</method>
		"""
		self.client=client
		#self.client.nul_nonfatal=True
		self.server=server
		self.parts=[]
		self.state="start"
		Zorp.log("form.info", 3, "%s: '%s' NUL nonfatal= %s" % (self.session.session_id, self.client,self.client.nul_nonfatal))
		Zorp.log("form.info", 3, "%s: dictionary= %s" % (self.session.session_id, dir(Stream)))
		while 1:
			Zorp.log("form.info", 3, "%s: while" % (self.session.session_id))
			try:
				line=self.client.readline()[:-2]
			except Stream.StreamException, (status,buffer):
				Zorp.log("form.info", 3, "%s: status=%u, buffer=%s" % (self.session.session_id,status,buffer.encode('string_escape')))
				self.abortProxy("Invalid data from client")
				
			Zorp.log("form.info", 3, "%s: read from client: %s" % (self.session.session_id, line.encode("string_escape")))
			try:
				self.processLine(line)
			except AbortProxyException:
				Zorp.log("form.info", 3, "%s: proxy done" % (self.session.session_id))
				return


class UrlEncodedProxy(AnyPy.AnyPyProxy):
	def config(self):
		Zorp.log("form.info",0, "%s: UrlEncodedProxy init" % (self.session.session_id))
		pass
	def proxyThread(self):
		self.form_policy=self.session.owner.proxy.form_policy
		Zorp.log("form.info",0, "%s: starting anypy thread" % (self.session.session_id))
		client_data=self.session.client_stream.read(65536)
		Zorp.log("form.info",0, "%s: %u " % (self.session.session_id, len(client_data)))
		self.request_url=self.session.owner.proxy.request_url
		newarglist=self.form_policy.urlencodedcheck(self.request_url,client_data)
		if newarglist == False:
			Zorp.log("form.policy",0, "%s: '%s'" % (self.session.session_id, "invalid form data"))
			self.set_verdict(2,"invalid form data")
			return
		self.session.server_stream.write(newarglist)
		Zorp.log("form.info",0, "%s: %s" % (self.session.session_id, "written to server"))


class FormProxy(Http.HttpProxy):
	def filterURL(self,cmd,url,version):
			"""
			"""
			Zorp.log("form.info",0, "%s: cmd=%s, url=%s, version=%s" % (self.session.session_id, cmd, url,version))
			
			l=url.split("?")
			if 1 == len (l):
				return Http.HTTP_REQ_ACCEPT
			(base,arglist)=l
			Zorp.log("form.info",0, "%s: base=%s, args=%s" % (self.session.session_id, base, arglist))
			newarglist=self.form_policy.urlencodedcheck(base,arglist)
			Zorp.log("form.info",0, "%s: args=%s" % (self.session.session_id, newarglist))
			if newarglist == False:
				Zorp.log("form.policy",0, "%s: rejected" % (self.session.session_id, ))
				return Http.HTTP_REQ_REJECT
			if newarglist:
				self.request_url="%s?%s"%(base,newarglist)
			else:
				self.request_url=base
			return Http.HTTP_REQ_ACCEPT

	def contentType(self,name,value):
		Zorp.log("http.info", 3, "%s: content-type=%s" % (self.session.session_id, value.encode("string_escape")))
		self.content_type=value
		if re.match("(?i)aPplication/x-www-form-urlencoded",value):
			self.request_stack["POST"] = (Http.HTTP_STK_DATA, UrlEncodedProxy)
			return Http.HTTP_HDR_ACCEPT
		if re.match("(?i)mUltipart/form-data",value):
			try:
				self.boundary=value.split("boundary=")[1].split(";")[0].strip()
			except IndexError:
				Zorp.log("http.info", 3, "%s: cannot obtain boundary" % (self.session.session_id))
				return Http.HTTP_HDR_DROP
			self.request_stack["POST"] = (Http.HTTP_STK_DATA, MultiPartProxy )
			#self.request_stack["POST"] = (Http.HTTP_STK_DATA, UrlEncodedProxy )
			return Http.HTTP_HDR_ACCEPT
		return Http.HTTP_HDR_ACCEPT

	def postProcess(self,method,url,version):
		Zorp.log("http.info", 3, "%s: POST" % (self.session.session_id))
		self.request_stack["POST"] = (Http.HTTP_STK_DATA, InvalidProxy )
		return Http.HTTP_REQ_ACCEPT

	def set_form_policy(self,policy,file_policy,drop_empty=1,silent_drop=0,one_blob=0,filename_pattern="^[a-zA-Z._\.]*",default_filename=None):
		#FIXME: there would be an easier way for the user if we could change request_stack in __post_config__
		self.form_policy=FormChecker(self.session,policy,file_policy,drop_empty,silent_drop,one_blob,filename_pattern,default_filename)
		Http.HttpProxy.config(self)
		self.request['GET'] = ( Http.HTTP_REQ_POLICY, self.filterURL)
		self.request_stack["POST"] = (Http.HTTP_STK_DATA, InvalidProxy)
		self.request_headers["CONTENT-TYPE"] = (Http.HTTP_HDR_POLICY, self.contentType)

