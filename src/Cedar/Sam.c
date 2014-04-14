// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE IT IN OTHER COUNTRIES. IMPORTING THIS
// SOFTWARE INTO OTHER COUNTRIES IS AT YOUR OWN RISK. SOME COUNTRIES
// PROHIBIT ENCRYPTED COMMUNICATIONS. USING THIS SOFTWARE IN OTHER
// COUNTRIES MIGHT BE RESTRICTED.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// Sam.c
// Security Accounts Manager

#include "CedarPch.h"

/*************************************************************
* Fully functional Samba NT Authentication
* Author: Tim Schneider
* Date: 12.04.2014
* E-Mail: schneider0tim@gmail.com
**************************************************************/

int base64_enc_len(unsigned int plainLen) {
	unsigned int n = plainLen;
	return (n + 2 - ((n + 2) % 3)) / 3 * 4;
}
 
pid_t OpenChildProcess(const char* path, char* const parameter[], int fd[] )
{
	int fds[2][2];
	pid_t pid;
 
	if( path == NULL || parameter == NULL || fd == NULL )
	{
		return (pid_t)-1;
	}
	
	if( pipe (fds[0]) != 0 )
	{
		return (pid_t)-1;
	}
	
	if( pipe (fds[1]) != 0 )
	{
		close(fds[0][0]);
		close(fds[0][1]);
		
		return (pid_t)-1;
	}
	
	pid = fork ();
	if (pid == (pid_t) 0) {
		// In child process
		// Write end of the file descriptor
		close (fds[0][1]);
		// Read end of the file descriptor
		close (fds[1][0]);
		
		// Take control of stdout and stdin
		if( dup2 (fds[0][0], STDIN_FILENO) < 0 || dup2 (fds[1][1], STDOUT_FILENO) < 0 )
		{
			close (fds[0][0]);
			close (fds[1][1]);
			
			_exit(EXIT_FAILURE);
		}
		
		// Replace the child process with the ntlm_auth
		int iError = execv(path, parameter);
 
		// We should never come here ...
		close (fds[0][0]);
		close (fds[1][1]);
			
		_exit(iError);
	}
	else if( pid > (pid_t)0 )
	{
		// Read end of the file descriptor
		close (fds[0][0]);
		// Write end of the file descriptor
		close (fds[1][1]);

		fd[0] = fds[1][0];
		fd[1] = fds[0][1];
		
		return pid;
	}
	else
	{
		// Read end of the file descriptor
		close (fds[0][0]);
		// Write end of the file descriptor
		close (fds[1][1]);
		
		// Write end of the file descriptor
		close (fds[0][1]);
		// Read end of the file descriptor
		close (fds[1][0]);
		
		return -1;
	}
}
void CloseChildProcess(pid_t pid, int* fd )
{
	if( fd != 0 )
	{
			close(fd[0]);
			close(fd[1]);
	}
	
	if( pid > 0 )
	{
		//Kill child
		kill( pid, SIGTERM );
	}
}

bool SmbAuthenticate(char* name, char* password, char* domainname, char* groupname, UCHAR* challenge8, UCHAR* MsChapV2_ClientResponse, UCHAR* nt_pw_hash_hash)
{
	if( name == NULL || password == NULL || domainname == NULL || groupname == NULL )
	{
		Debug("Sam.c - SmbAuthenticate - wrong password parameter\n");
		return false;
	}
	
	if( password[0] == '\0' && ( challenge8 == NULL || MsChapV2_ClientResponse == NULL || nt_pw_hash_hash == NULL ) )
	{
		Debug("Sam.c - SmbAuthenticate - wrong MsCHAPv2 parameter\n");
		return false;
	}
	
	bool bAuth = false;
	char czBuffer[255];
	
	memset( czBuffer, 0, sizeof(czBuffer) );
	
	int fds[2];
	FILE* out, *in;
	pid_t pid;
	char* parameter[4];
	
	// Take care of domainname! this is userinput!
	// dunno if its enough -> allowed chars are:
	// "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// "abcdefghijklmnopqrstuvwxyz"
	// "0123456789"
	// " ()-_#%&.";
	// possible to exploit?! -> single quote the parameter to disable special chars!
	
	// Truncate string if unsafe char 
	EnSafeStr(domainname, '\0');
	
	// What happens here if someone (the bad guy) sends a wrong domainname?
	if( strlen( domainname ) > 255 )
	{
		// there is no domainname longer then 255 chars! :D
		// http://tools.ietf.org/html/rfc1035 section 2.3.4
		domainname[255] = '\0';
	}

	// DNS Name 255
	// OU names are limited to 64 characters
	// cmdline 32 + 1
	char requiremember[352];

	if( strlen(groupname) > 1 )
	{
		// Truncate string if unsafe char 
		EnSafeStr(groupname, '\0');
		
		snprintf( requiremember, sizeof(requiremember), "--require-membership-of=%s\\%s", domainname, groupname );
		
		parameter[0] = "ntlm_auth";
		parameter[1] = "--helper-protocol=ntlm-server-1";
		parameter[2] = requiremember;
		parameter[3] = 0;
	}else
	{
		parameter[0] = "ntlm_auth";
		parameter[1] = "--helper-protocol=ntlm-server-1";
		parameter[2] = 0;
	}
	
	pid = OpenChildProcess("/usr/bin/ntlm_auth", parameter, fds );
	
	if( pid < 0 )
	{
		Debug("Sam.c - SmbCheckLogon - error fork child process (ntlm_auth)\n");
		return false;
	}
	
	out = fdopen (fds[1], "w");
	if( out == 0 )
	{
		CloseChildProcess(pid, fds);
		
		//printf("Konnte die Pipe out nicht öffnen\n");
		Debug("Sam.c - cant open pipe out\n");
		return false;
	}

	in = fdopen (fds[0], "r");
	if( in == 0 )
	{
		fclose(out);
		CloseChildProcess(pid, fds);
		
		//printf("Konnte die Pipe in nicht öffnen\n");
		Debug("Sam.c - cant open pipe out\n");
		return false;
	}

	if( base64_enc_len( strlen( name) ) < sizeof( czBuffer )-1 &&
		base64_enc_len( strlen( password ) ) < sizeof( czBuffer )-1 &&
		base64_enc_len( strlen( domainname ) ) < sizeof( czBuffer )-1 )
	{
		// Strange behavior - function does not terminate string :S
		unsigned int end = B64_Encode( czBuffer, name, strlen(name) );
		czBuffer[end] = '\0';
		fputs( "Username:: ", out );
		fputs( czBuffer, out );
		fputs( "\n", out );
		Debug("Username: %s\n", czBuffer);
		czBuffer[0] = 0;

		end = B64_Encode( czBuffer, domainname, strlen(domainname) );
		czBuffer[end] = '\0';
		fputs( "NT-Domain:: ", out );
		fputs( czBuffer, out );
		fputs( "\n", out );
		Debug("NT-Domain: %s\n", czBuffer);
		czBuffer[0] = 0;

		if( password[0] != '\0' )
		{
			Debug("Password authentication\n");
			end = B64_Encode( czBuffer, password, strlen(password) );
			czBuffer[end] = '\0';
			fputs( "Password:: ", out );
			fputs( czBuffer, out );
			fputs( "\n", out );
			Debug("Password: %s\n", czBuffer);
			czBuffer[0] = 0;
		}
		else
		{
			Debug("MsChapV2 authentication\n");
			char* pMsChapV2_ClientResponse = CopyBinToStr(MsChapV2_ClientResponse, 24);
			end = B64_Encode( czBuffer, pMsChapV2_ClientResponse, 48 );
			czBuffer[end] = '\0';
			fputs( "NT-Response:: ", out );
			fputs( czBuffer, out );
			fputs( "\n", out );
			Debug("NT-Response:: %s\n", czBuffer);
			czBuffer[0] = 0;
			Free(pMsChapV2_ClientResponse);
 
			char* pChallenge8 = CopyBinToStr(challenge8,8);
			end = B64_Encode( czBuffer, pChallenge8 , 16 );
			czBuffer[end] = '\0';
			fputs( "LANMAN-Challenge:: ", out );
			fputs( czBuffer, out );
			fputs( "\n", out );
			Debug("LANMAN-Challenge:: %s\n", czBuffer);
			czBuffer[0] = 0;
			Free(pChallenge8);
 
			fputs( "Request-User-Session-Key: Yes\n", out );
			//fputs( "Request-LanMan-Session-Key: Yes\n", out );
 		}

		//Samba!
		//mux_printf(mux_id, "LANMAN-Session-Key: %s\n", hex_lm_key);
		//mux_printf(mux_id, "User-Session-Key: %s\n", hex_user_session_key);
 
		// SoftEther
		//Copy(ret_pw_hash_hash, response->UserSessionKey, 16);
 
		// Decision
		// User-Session-Key as char array :)


		// Start authentication
		fputs( ".\n", out );

		fflush (out);

		// Request send!
		
		// This should be a Dynamic Buffer!
		// but what happens if ntlm_auth sends trash back?
		// we get User-Session-Key: + >=24 as Base64 coded worst -> buffer of 300 per line should be fine!
		// otherwise someone could flood our ram (ntlm_auth)
		char answer[300];
		answer[0] = 0;

		while( fgets( answer, sizeof( answer )-1, in ) )
		{
			// Copy Paste from Samba source4/utils/ntlm_auth.c 
			/* Indicates a base64 encoded structure */
			if( strncmp(answer, ".\n", sizeof(answer)-1 ) == 0 )
			{
				//printf("Ende der Uebertragung!\n");
				break;
			}

			char* parameter = strstr(answer, ":: ");
			if (!parameter) {
				parameter = strstr(answer, ": ");

				if (!parameter) {
					//DEBUG(0, ("Parameter not found!\n"));
					//fprintf(stderr, "Error: Parameter not found!\n.\n");
					continue;
				}

				parameter[0] ='\0';
				parameter++;
				parameter[0] ='\0';
				parameter++;

				char* newline  = strstr(parameter, "\n");
				if( newline )
					newline[0] = '\0'; // overwrite \n
			} else {
				parameter[0] ='\0';
				parameter++;
				parameter[0] ='\0';
				parameter++;
				parameter[0] ='\0';
				parameter++;

				// inplace decode
				// risk! -> no influence of the Decode64 code!
				// better to make it dynamic for production ... 
				// but decode gets smaller for sure so we could use same space ?! 
				end = Decode64(parameter, parameter);
				parameter[end] = '\0';
			}

			if( strncmp(answer, "Authenticated", sizeof(answer)-1 ) == 0 )
			{
				if( strcmp(parameter, "Yes") == 0 )
				{
					Debug("Authentifiziert!\n");
					bAuth = true;
				}
				else if( strcmp(parameter, "No") == 0 )
				{
					Debug("Keine Authentifizierung!\n");
					bAuth = false;
				}
			}
			else if( strncmp(answer, "User-Session-Key", sizeof(answer)-1 ) == 0 )
			{
				if(nt_pw_hash_hash != NULL)
				{
					BUF* Buf = StrToBin(parameter);
					Copy(nt_pw_hash_hash, Buf->Buf, 16);
					FreeBuf(Buf);
					//printf("User Session Key!\n");
				}
			}

		}
	}
	
	fclose(in);
	fclose(out);
	
	CloseChildProcess( pid, fds );

	return bAuth;
}


bool SmbCheckLogon(char* name, char* password, char* domainname, char* groupname)
{
	return SmbAuthenticate( name, password, domainname, groupname, NULL, NULL, NULL);
}

bool SmbPerformMsChapV2Auth(char* name, char* domainname, char* groupname, UCHAR* challenge8, UCHAR* MsChapV2_ClientResponse, UCHAR* nt_pw_hash_hash)
{
	return SmbAuthenticate( name, "", domainname, groupname, challenge8, MsChapV2_ClientResponse, nt_pw_hash_hash);
}


// Password encryption
void SecurePassword(void *secure_password, void *password, void *random)
{
	BUF *b;
	// Validate arguments
	if (secure_password == NULL || password == NULL || random == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, password, SHA1_SIZE);
	WriteBuf(b, random, SHA1_SIZE);
	Hash(secure_password, b->Buf, b->Size, true);

	FreeBuf(b);
}

// Generate 160bit random number
void GenRamdom(void *random)
{
	// Validate arguments
	if (random == NULL)
	{
		return;
	}

	Rand(random, SHA1_SIZE);
}

// Anonymous authentication of user
bool SamAuthUserByAnonymous(HUB *h, char *username)
{
	bool b = false;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return false;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_ANONYMOUS)
				{
					b = true;
				}
			}
			Unlock(u->lock);
		}
		ReleaseUser(u);
	}
	AcUnlock(h);

	return b;
}

// Plaintext password authentication of user
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast, UCHAR *mschap_v2_server_response_20)
{
	wchar_t *groupname = NULL;
	
	bool b = false;
	wchar_t *name = NULL;
	bool auth_by_nt = false;
	HUB *h;
	// Validate arguments
	if (hub == NULL || c == NULL || username == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		return false;
	}

	h = hub;

	AddRef(h->ref);

	// Get the user name on authentication system
	AcLock(hub);
	{
		USER *u;
		u = AcGetUser(hub, ast == false ? username : "*");
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_RADIUS)
				{
					// Radius authentication
					AUTHRADIUS *auth = (AUTHRADIUS *)u->AuthData;
					if (ast || auth->RadiusUsername == NULL || UniStrLen(auth->RadiusUsername) == 0)
					{
						name = CopyStrToUni(username);
					}
					else
					{
						name = CopyUniStr(auth->RadiusUsername);
					}
					auth_by_nt = false;
				}
				else if (u->AuthType == AUTHTYPE_NT)
				{
					// NT authentication
					AUTHNT *auth = (AUTHNT *)u->AuthData;
					if (ast || auth->NtUsername == NULL || UniStrLen(auth->NtUsername) == 0)
					{
						name = CopyStrToUni(username);
					}
					else
					{
						name = CopyUniStr(auth->NtUsername);
					}
					
					groupname = CopyStrToUni(u->GroupName);
					
					auth_by_nt = true;
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(hub);

	if (name != NULL)
	{
		if (auth_by_nt == false)
		{
			// Radius authentication
			char radius_server_addr[MAX_SIZE];
			UINT radius_server_port;
			char radius_secret[MAX_SIZE];
			char suffix_filter[MAX_SIZE];
			wchar_t suffix_filter_w[MAX_SIZE];
			UINT interval;

			Zero(suffix_filter, sizeof(suffix_filter));
			Zero(suffix_filter_w, sizeof(suffix_filter_w));

			// Get the Radius server information
			if (GetRadiusServerEx2(hub, radius_server_addr, sizeof(radius_server_addr), &radius_server_port, radius_secret, sizeof(radius_secret), &interval, suffix_filter, sizeof(suffix_filter)))
			{
				Unlock(hub->lock);

				StrToUni(suffix_filter_w, sizeof(suffix_filter_w), suffix_filter);

				if (UniIsEmptyStr(suffix_filter_w) || UniEndWith(name, suffix_filter_w))
				{
					// Attempt to login
					b = RadiusLogin(c, radius_server_addr, radius_server_port,
						radius_secret, StrLen(radius_secret),
						name, password, interval, mschap_v2_server_response_20);
				}

				Lock(hub->lock);
			}
			else
			{
				HLog(hub, "LH_NO_RADIUS_SETTING", name);
			}
		}
		else
		{
			// NT authentication (Not available for non-Win32)
#ifdef	OS_WIN32
			IPC_MSCHAP_V2_AUTHINFO mschap;
			Unlock(hub->lock);

			if (ParseAndExtractMsChapV2InfoFromPassword(&mschap, password) == false)
			{
				// Plaintext password authentication
				b = MsCheckLogon(name, password);
			}
			else
			{
				UCHAR challenge8[8];
				UCHAR nt_pw_hash_hash[16];
				char nt_name[MAX_SIZE];

				UniToStr(nt_name, sizeof(nt_name), name);

				// MS-CHAPv2 authentication
				MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge,
					mschap.MsChapV2_ServerChallenge,
					mschap.MsChapV2_PPPUsername);

				Debug("MsChapV2_PPPUsername = %s, nt_name = %s\n", mschap.MsChapV2_PPPUsername, nt_name);

				b = MsPerformMsChapV2AuthByLsa(nt_name, challenge8, mschap.MsChapV2_ClientResponse, nt_pw_hash_hash);

				if (b)
				{
					if (mschap_v2_server_response_20 != NULL)
					{
						MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
							mschap.MsChapV2_ClientResponse, challenge8);
					}
				}
			}

			Lock(hub->lock);
#else	// OS_WIN32
			// Nothing to do other than Win32
 
			IPC_MSCHAP_V2_AUTHINFO mschap;
			Unlock(hub->lock);
 
			char nt_name[MAX_SIZE];
			char nt_username[MAX_SIZE];
			char nt_groupname[MAX_SIZE];
			char nt_domainname[MAX_SIZE];
			// sicher ist sicher :D std sagt zwar das ein Array leer ist ... 
			nt_groupname[0] = 0;
 
			UniToStr(nt_name, sizeof(nt_name), name);
 
			if( groupname != NULL )
				UniToStr(nt_groupname, sizeof(nt_groupname), groupname);
 
			ParseNtUsername(nt_name, nt_username, sizeof(nt_username), nt_domainname, sizeof(nt_domainname), false);
 
			if (ParseAndExtractMsChapV2InfoFromPassword(&mschap, password) == false)
			{
				// Plaintext password authentication
 
				b = SmbCheckLogon(nt_username, password, nt_domainname, nt_groupname);
			}
			else
			{
				UCHAR challenge8[8];
				UCHAR nt_pw_hash_hash[16];
 
				// MS-CHAPv2 authentication
				MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge,
					mschap.MsChapV2_ServerChallenge,
					mschap.MsChapV2_PPPUsername);
 
				Debug("MsChapV2_PPPUsername = %s, nt_name = %s\n", mschap.MsChapV2_PPPUsername, nt_name);
 
				b = SmbPerformMsChapV2Auth(nt_username, nt_domainname, nt_groupname, challenge8, mschap.MsChapV2_ClientResponse, nt_pw_hash_hash);
 
				if (b)
				{
					if (mschap_v2_server_response_20 != NULL)
					{
						MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
							mschap.MsChapV2_ClientResponse, challenge8);
					}
				}
			}
 
			Lock(hub->lock);
#endif	// OS_WIN32
		}

		// Memory release
		if( groupname != NULL )
			Free(groupname);
		Free(name);
	}

	ReleaseHub(h);

	return b;
}

// Certificate authentication of user
bool SamAuthUserByCert(HUB *h, char *username, X *x)
{
	bool b = false;
	// Validate arguments
	if (h == NULL || username == NULL || x == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) != 0)
	{
		return false;
	}

	// Check expiration date
	if (CheckXDateNow(x) == false)
	{
		return false;
	}

	// Check the Certification Revocation List
	if (IsValidCertInHub(h, x) == false)
	{
		// Bad
		wchar_t tmp[MAX_SIZE * 2];

		// Log the contents of the certificate
		GetAllNameFromX(tmp, sizeof(tmp), x);

		HLog(h, "LH_AUTH_NG_CERT", username, tmp);
		return false;
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_USERCERT)
				{
					// Check whether to matche with the registered certificate
					AUTHUSERCERT *auth = (AUTHUSERCERT *)u->AuthData;
					if (CompareX(auth->UserX, x))
					{
						b = true;
					}
				}
				else if (u->AuthType == AUTHTYPE_ROOTCERT)
				{
					// Check whether the certificate has been signed by the root certificate
					AUTHROOTCERT *auth = (AUTHROOTCERT *)u->AuthData;
					if (h->HubDb != NULL)
					{
						LockList(h->HubDb->RootCertList);
						{
							X *root_cert;
							root_cert = GetIssuerFromList(h->HubDb->RootCertList, x);
							if (root_cert != NULL)
							{
								b = true;
								if (auth->CommonName != NULL && UniIsEmptyStr(auth->CommonName) == false)
								{
									// Compare the CN
									if (UniStrCmpi(x->subject_name->CommonName, auth->CommonName) != 0)
									{
										b = false;
									}
								}
								if (auth->Serial != NULL && auth->Serial->size >= 1)
								{
									// Compare the serial number
									if (CompareXSerial(x->serial, auth->Serial) == false)
									{
										b = false;
									}
								}
							}
						}
						UnlockList(h->HubDb->RootCertList);
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (b)
	{
		wchar_t tmp[MAX_SIZE * 2];

		// Log the contents of the certificate
		GetAllNameFromX(tmp, sizeof(tmp), x);

		HLog(h, "LH_AUTH_OK_CERT", username, tmp);
	}

	return b;
}

// Get the root certificate that signed the specified certificate from the list
X *GetIssuerFromList(LIST *cert_list, X *cert)
{
	UINT i;
	X *ret = NULL;
	// Validate arguments
	if (cert_list == NULL || cert == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(cert_list);i++)
	{
		X *x = LIST_DATA(cert_list, i);
		// Name comparison
		if (CheckXDateNow(x))
		{
			if (CompareName(x->subject_name, cert->issuer_name))
			{
				// Get the public key of the root certificate
				K *k = GetKFromX(x);

				if (k != NULL)
				{
					// Check the signature
					if (CheckSignature(cert, k))
					{
						ret = x;
					}
					FreeK(k);
				}
			}
		}
		if (CompareX(x, cert))
		{
			// Complete identical
			ret = x;
		}
	}

	return ret;
}

// Get the policy to be applied for the user
POLICY *SamGetUserPolicy(HUB *h, char *username)
{
	POLICY *ret = NULL;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return NULL;
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u)
		{
			USERGROUP *g = NULL;
			Lock(u->lock);
			{
				if (u->Policy != NULL)
				{
					ret = ClonePolicy(u->Policy);
				}

				g = u->Group;

				if (g != NULL)
				{
					AddRef(g->ref);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
			u = NULL;

			if (ret == NULL)
			{
				if (g != NULL)
				{
					Lock(g->lock);
					{
						ret = ClonePolicy(g->Policy);
					}
					Unlock(g->lock);
				}
			}

			if (g != NULL)
			{
				ReleaseGroup(g);
			}
		}
	}
	AcUnlock(h);

	return ret;
}

// Password authentication of user
bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password, char *mschap_v2_password, UCHAR *mschap_v2_server_response_20, UINT *err)
{
	bool b = false;
	UCHAR secure_password_check[SHA1_SIZE];
	bool is_mschap = false;
	IPC_MSCHAP_V2_AUTHINFO mschap;
	UINT dummy = 0;
	// Validate arguments
	if (h == NULL || username == NULL || secure_password == NULL)
	{
		return false;
	}
	if (err == NULL)
	{
		err = &dummy;
	}

	*err = 0;

	Zero(&mschap, sizeof(mschap));

	is_mschap = ParseAndExtractMsChapV2InfoFromPassword(&mschap, mschap_v2_password);

	if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0)
	{
		// Administrator mode
		SecurePassword(secure_password_check, h->SecurePassword, random);
		if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_PASSWORD)
				{
					AUTHPASSWORD *auth = (AUTHPASSWORD *)u->AuthData;

					if (is_mschap == false)
					{
						// Normal password authentication
						SecurePassword(secure_password_check, auth->HashedKey, random);
						if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
						{
							b = true;
						}
					}
					else
					{
						// MS-CHAP v2 authentication via PPP
						UCHAR challenge8[8];
						UCHAR client_response[24];

						if (IsZero(auth->NtLmSecureHash, MD5_SIZE))
						{
							// NTLM hash is not registered in the user account
							*err = ERR_MSCHAP2_PASSWORD_NEED_RESET;
						}
						else
						{
							UCHAR nt_pw_hash_hash[16];
							Zero(challenge8, sizeof(challenge8));
							Zero(client_response, sizeof(client_response));

							MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge, mschap.MsChapV2_ServerChallenge,
								mschap.MsChapV2_PPPUsername);

							MsChapV2Client_GenerateResponse(client_response, challenge8, auth->NtLmSecureHash);

							if (Cmp(client_response, mschap.MsChapV2_ClientResponse, 24) == 0)
							{
								// Hash matched
								b = true;

								// Calculate the response
								GenerateNtPasswordHashHash(nt_pw_hash_hash, auth->NtLmSecureHash);
								MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
									client_response, challenge8);
							}
						}
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	return b;
}

// Make sure that the user exists
bool SamIsUser(HUB *h, char *username)
{
	bool b;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return false;
	}

	AcLock(h);
	{
		b = AcIsUser(h, username);
	}
	AcUnlock(h);

	return b;
}

// Get the type of authentication used by the user
UINT SamGetUserAuthType(HUB *h, char *username)
{
	UINT authtype;
	// Validate arguments
	if (h == NULL || username == NULL)
	{
		return INFINITE;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u == NULL)
		{
			authtype = INFINITE;
		}
		else
		{
			authtype = u->AuthType;
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	return authtype;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
