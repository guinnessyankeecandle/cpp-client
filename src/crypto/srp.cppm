module;
#include <Python.h>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
export module securemsg.crypto.srp;

struct PyObjDeleter {
    void operator()(PyObject* p) const noexcept { Py_XDECREF(p); }
};
using PyPtr = std::unique_ptr<PyObject, PyObjDeleter>;

static void checkPyErr(const char* where) {
    if (PyErr_Occurred()) {
        PyErr_Print();
        throw std::runtime_error(std::string("SRP: ") + where + " failed");
    }
}

static std::vector<uint8_t> hexDecode(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    return out;
}

static std::string hexEncode(const uint8_t* data, const std::size_t len) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out(len * 2, '\0');
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2]     = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0xf];
    }
    return out;
}

static std::string bytesToHex(PyObject* bytesObj) {
    const char* data = PyBytes_AsString(bytesObj);
    const auto len = static_cast<std::size_t>(PyBytes_Size(bytesObj));
    return hexEncode(reinterpret_cast<const uint8_t*>(data), len);
}

export struct SrpProof {
    std::string clientPublicHex;
    std::string clientProofHex;
};

export class SrpSession {
public:
    static std::string computeVerifier(const std::string& username,
                                       const std::string& password,
                                       std::string& saltHexOut) {
        const auto [srp, sha256, ng4096] = srpConstants();

        // create_salted_verification_key(username, password, SHA256, NG_4096, None, None, salt_len=32)
        const PyPtr result(PyObject_CallMethod(srp.get(), "create_salted_verification_key",
                                               "ssOOOOi", username.c_str(), password.c_str(),
                                               sha256.get(), ng4096.get(), Py_None, Py_None, 32));
        checkPyErr("create_salted_verification_key");

        saltHexOut = bytesToHex(PyTuple_GetItem(result.get(), 0));
        return bytesToHex(PyTuple_GetItem(result.get(), 1));
    }

    SrpProof computeProof(const std::string& username,
                          const std::string& password,
                          const std::string& srpSaltHex,
                          const std::string& serverPublicHex) {
        const auto [srp, sha256, ng4096] = srpConstants();

        // usr = srp.User(username, password, SHA256, NG_4096)
        m_srpUser.reset(PyObject_CallMethod(srp.get(), "User", "ssOO",
                                            username.c_str(), password.c_str(),
                                            sha256.get(), ng4096.get()));
        checkPyErr("srp.User");

        // uname, A = usr.start_authentication()
        const PyPtr authTuple(PyObject_CallMethod(m_srpUser.get(), "start_authentication", nullptr));
        checkPyErr("start_authentication");
        const std::string clientPublicHex = bytesToHex(PyTuple_GetItem(authTuple.get(), 1));

        // M1 = usr.process_challenge(salt_bytes, B_bytes)
        const std::vector<uint8_t> saltBytes = hexDecode(srpSaltHex);
        const std::vector<uint8_t> BBytes    = hexDecode(serverPublicHex);

        const PyPtr saltObj(PyBytes_FromStringAndSize(
            reinterpret_cast<const char*>(saltBytes.data()),
            static_cast<Py_ssize_t>(saltBytes.size())));
        const PyPtr BObj(PyBytes_FromStringAndSize(
            reinterpret_cast<const char*>(BBytes.data()),
            static_cast<Py_ssize_t>(BBytes.size())));

        const PyPtr M1(PyObject_CallMethod(m_srpUser.get(), "process_challenge",
                                           "OO", saltObj.get(), BObj.get()));
        checkPyErr("process_challenge");

        if (M1.get() == Py_None)
            throw std::runtime_error("SRP: server public value rejected");

        return {clientPublicHex, bytesToHex(M1.get())};
    }

    [[nodiscard]] bool verifyServerProof(const std::string& serverProofHex) const {
        if (!m_srpUser)
            throw std::runtime_error("SRP: cannot verify before completing handshake");

        const std::vector<uint8_t> M2Bytes = hexDecode(serverProofHex);
        const PyPtr M2(PyBytes_FromStringAndSize(
            reinterpret_cast<const char*>(M2Bytes.data()),
            static_cast<Py_ssize_t>(M2Bytes.size())));

        PyObject_CallMethod(m_srpUser.get(), "verify_session", "O", M2.get());
        checkPyErr("verify_session");

        const PyPtr auth(PyObject_CallMethod(m_srpUser.get(), "authenticated", nullptr));
        checkPyErr("authenticated");

        return PyObject_IsTrue(auth.get()) == 1;
    }

private:
    struct SrpConsts { PyPtr srp, sha256, ng4096; };

    static SrpConsts srpConstants() {
        if (!Py_IsInitialized()) {
            Py_Initialize();
            // Match the server: srp_session.py calls srp.rfc5054_enable() at module load
            const PyPtr srp_init(PyImport_ImportModule("srp"));
            if (srp_init)
                PyObject_CallMethod(srp_init.get(), "rfc5054_enable", nullptr);
            PyErr_Clear();
        }

        PyPtr srp(PyImport_ImportModule("srp"));
        if (!srp) { PyErr_Print(); throw std::runtime_error("SRP: cannot import pysrp"); }

        PyPtr sha256(PyObject_GetAttrString(srp.get(), "SHA256"));
        PyPtr ng4096(PyObject_GetAttrString(srp.get(), "NG_4096"));
        checkPyErr("loading SRP constants");

        return {std::move(srp), std::move(sha256), std::move(ng4096)};
    }

    PyPtr m_srpUser;
};
