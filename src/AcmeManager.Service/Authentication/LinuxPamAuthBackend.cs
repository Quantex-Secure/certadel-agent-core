using System.Runtime.InteropServices;
using System.Runtime.Versioning;

using AcmeManager.Core.Authentication;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// Validates Linux credentials via <c>libpam</c> (<c>pam_start</c> →
/// <c>pam_authenticate</c> → <c>pam_acct_mgmt</c> → <c>pam_end</c>). Service
/// stack defaults to <c>"login"</c>; override via <see cref="ServiceName"/>
/// to use e.g. a custom <c>/etc/pam.d/acme-manager</c> profile.
///
/// PAM expects the conversation callback's <c>pam_response</c> array and
/// strings to be allocated with libc <c>malloc</c> (it calls <c>free</c>
/// on them). We allocate via P/Invoke to <c>libc</c> to satisfy that
/// contract reliably across glibc/musl.
///
/// Caveat: written against the glibc PAM ABI without on-host validation
/// here. Run a real Linux smoke test before relying on it in production.
///
/// This backend <em>authenticates</em> and then resolves the user's group
/// membership through <see cref="IUnixGroupResolver"/>. The <c>Auth:AllowedGroup</c>
/// decision itself is made by <see cref="AllowedGroupAuthorizer"/> — the same
/// rule, in the same place, as on Windows. A user whose groups can't be
/// resolved is reported as authenticated with no groups, which that decision
/// refuses.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class LinuxPamAuthBackend(IUnixGroupResolver groupResolver) : IAuthBackend
{
    private const string LibPam = "libpam.so.0";
    private const string LibC = "libc";

    private const int PAM_SUCCESS = 0;
    private const int PAM_PROMPT_ECHO_OFF = 1;
    private const int PAM_PROMPT_ECHO_ON = 2;

    public string ServiceName { get; init; } = "login";

    [StructLayout(LayoutKind.Sequential)]
    private struct PamMessage
    {
        public int MsgStyle;
        public IntPtr Msg;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PamResponse
    {
        public IntPtr Resp;
        public int RespRetCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PamConv
    {
        public IntPtr Conv;
        public IntPtr AppData;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int PamConvFunc(int numMsg, IntPtr msg, out IntPtr resp, IntPtr appdataPtr);

    [LibraryImport(LibPam, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int pam_start(string service, string user, ref PamConv conv, out IntPtr pamh);

    [LibraryImport(LibPam)]
    private static partial int pam_authenticate(IntPtr pamh, int flags);

    [LibraryImport(LibPam)]
    private static partial int pam_acct_mgmt(IntPtr pamh, int flags);

    [LibraryImport(LibPam)]
    private static partial int pam_end(IntPtr pamh, int status);

    [LibraryImport(LibC)]
    private static partial IntPtr malloc(nuint size);

    public async ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct)
    {
        var authenticated = AuthenticateWithPam(username, password);
        if (!authenticated.Success)
        {
            return authenticated;
        }

        IReadOnlyList<string> groups;
        try
        {
            groups = await groupResolver.ResolveAsync(username, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return AuthResult.Fail($"Could not resolve group membership for '{username}': {ex.Message}");
        }
        return AuthResult.Ok(username, groups);
    }

    private AuthResult AuthenticateWithPam(string username, string password)
    {
        // Keep delegate + appdata pinned for the duration of the call so the GC
        // doesn't move/collect them while PAM is reading them through P/Invoke.
        var convFunc = new PamConvFunc(ConversationCallback);
        var convFuncPtr = Marshal.GetFunctionPointerForDelegate(convFunc);

        // appdata = pointer to a malloc'd UTF-8 password buffer. Conv callback frees nothing
        // (we free below); PAM frees the responses we return.
        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password + "\0");
        var passwordPtr = malloc((nuint)passwordBytes.Length);
        if (passwordPtr == IntPtr.Zero)
        {
            return AuthResult.Fail("Out of memory allocating PAM password buffer");
        }
        Marshal.Copy(passwordBytes, 0, passwordPtr, passwordBytes.Length);

        var conv = new PamConv { Conv = convFuncPtr, AppData = passwordPtr };

        try
        {
            var rc = pam_start(ServiceName, username, ref conv, out var pamh);
            if (rc != PAM_SUCCESS)
            {
                return AuthResult.Fail($"pam_start returned {rc}");
            }

            try
            {
                rc = pam_authenticate(pamh, 0);
                if (rc != PAM_SUCCESS)
                {
                    return AuthResult.Fail($"pam_authenticate returned {rc}");
                }

                rc = pam_acct_mgmt(pamh, 0);
                if (rc != PAM_SUCCESS)
                {
                    return AuthResult.Fail($"pam_acct_mgmt returned {rc}");
                }

                return AuthResult.Ok(username);
            }
            finally
            {
                pam_end(pamh, rc);
            }
        }
        finally
        {
            ZeroAndFree(passwordPtr, passwordBytes.Length);
            GC.KeepAlive(convFunc);
        }
    }

    private static int ConversationCallback(int numMsg, IntPtr msgArrayPtr, out IntPtr respArrayPtr, IntPtr appdataPtr)
    {
        respArrayPtr = IntPtr.Zero;
        if (numMsg <= 0 || msgArrayPtr == IntPtr.Zero)
        {
            return 1; // PAM_CONV_ERR
        }

        // glibc PAM: msg is `pam_message **` — an array of pointers to pam_message.
        var msgPtrSize = IntPtr.Size;
        var respSize = Marshal.SizeOf<PamResponse>() * numMsg;
        respArrayPtr = malloc((nuint)respSize);
        if (respArrayPtr == IntPtr.Zero) return 1;

        for (var i = 0; i < numMsg; i++)
        {
            var msgPtr = Marshal.ReadIntPtr(msgArrayPtr, i * msgPtrSize);
            var msg = Marshal.PtrToStructure<PamMessage>(msgPtr);

            IntPtr respStr = IntPtr.Zero;
            if (msg.MsgStyle is PAM_PROMPT_ECHO_OFF or PAM_PROMPT_ECHO_ON)
            {
                // Hand back a duplicate of the password buffer — PAM frees it.
                respStr = DuplicateCString(appdataPtr);
            }

            var resp = new PamResponse { Resp = respStr, RespRetCode = 0 };
            Marshal.StructureToPtr(resp, respArrayPtr + i * Marshal.SizeOf<PamResponse>(), false);
        }

        return PAM_SUCCESS;
    }

    private static IntPtr DuplicateCString(IntPtr source)
    {
        if (source == IntPtr.Zero) return IntPtr.Zero;
        var len = 0;
        while (Marshal.ReadByte(source, len) != 0) len++;
        var copy = malloc((nuint)(len + 1));
        if (copy == IntPtr.Zero) return IntPtr.Zero;
        unsafe
        {
            Buffer.MemoryCopy((void*)source, (void*)copy, len + 1, len + 1);
        }
        return copy;
    }

    private static void ZeroAndFree(IntPtr ptr, int length)
    {
        if (ptr == IntPtr.Zero) return;
        for (var i = 0; i < length; i++)
        {
            Marshal.WriteByte(ptr, i, 0);
        }
        free(ptr);
    }

    [LibraryImport(LibC)]
    private static partial void free(IntPtr ptr);
}