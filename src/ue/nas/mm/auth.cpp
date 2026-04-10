//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "mm.hpp"

#include <cstring>
#include <lib/nas/utils.hpp>
#include <ue/nas/keys.hpp>

namespace nr::ue
{

static const uint8_t EDHOC_PSK_CRED_I[] = {
    0xA2, 0x02, 0x69, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6F,
    0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20,
    0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF,
    0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};
static const uint8_t EDHOC_PSK_CRED_R[] = {
    0xA2, 0x02, 0x69, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x64, 0x65,
    0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20,
    0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF,
    0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};
static constexpr uint8_t EDHOC_EMSK_EXPORTER_LABEL = 27;
static constexpr size_t EDHOC_EMSK_LEN = 64;
static constexpr size_t EDHOC_KAUSF_LEN = 32;

void NasMm::receiveAuthenticationRequest(const nas::AuthenticationRequest &msg)
{
    m_logger->debug("Authentication Request received");

    if (!m_usim->isValid())
    {
        m_logger->warn("Authentication request is ignored. USIM is invalid");
        return;
    }

    m_timers->t3520.start();

    // with eapMessage → EAP-based path, which also includes EDHOC bootstrap
    // without eapMessage → normal 5G-AKA path
    if (msg.eapMessage.has_value())
        receiveAuthenticationRequestEap(msg);
    else
        receiveAuthenticationRequest5gAka(msg);
}

void NasMm::receiveAuthenticationRequestEap(const nas::AuthenticationRequest &msg)
{
    Plmn currentPlmn = m_base->shCtx.getCurrentPlmn();
    if (!currentPlmn.hasValue())
        return;

    auto handleEdhocNotification = [this, &msg, &currentPlmn](const eap::EapNotification &receivedEap) {
        EadItemsC ead1{};
        EadItemsC ead2{};
        EadItemsC ead3{};
        EadItemsC ead4{};
        EdhocMessageBuffer message1{};
        EdhocMessageBuffer message2{};
        EdhocMessageBuffer message3{};
        EdhocMessageBuffer message4{};
        IdCred idCredR{};
        uint8_t cI = 0;
        uint8_t cR = 0;
        uint8_t prkOut[SHA256_DIGEST_LEN] = {};
        bool hasIdCredR = false;
        CredentialC credI{};
        int8_t rc = 0;

        // If the incoming EAP payload is a Notification and its content is exactly:
        // “This is not ordinary EAP-AKA'; this is the prototype trigger for the EDHOC-PSK path.”
        if (receivedEap.rawData.toHexString() != OctetString::FromAscii("EDHOC-START").toHexString())
        {
            if (m_edhocAwaitingMessage4)
            {
                // Third EDHOC leg on UE: receive/process message_4, then acknowledge it.
                if (receivedEap.rawData.length() <= 0 ||
                    receivedEap.rawData.length() > static_cast<int>(sizeof(message4.content)))
                {
                    m_logger->err("EDHOC: invalid message_4 length [%d]", receivedEap.rawData.length());
                    m_edhocAwaitingMessage4 = false;
                    return false;
                }

                message4.len = receivedEap.rawData.length();
                std::memcpy(message4.content, receivedEap.rawData.data(), message4.len);

                rc = initiator_process_message_4(&m_edhocInitiator, &message4, &ead4);
                if (rc != 0)
                {
                    m_logger->err("EDHOC: initiator_process_message_4 failed [%d]", rc);
                    m_edhocAwaitingMessage4 = false;
                    return false;
                }

                if (!m_usim->m_nonCurrentNsCtx)
                {
                    m_logger->err("EDHOC: NAS security context missing after message_4");
                    m_edhocAwaitingMessage4 = false;
                    return false;
                }

                uint8_t emsk[EDHOC_EMSK_LEN] = {};
                rc = initiator_edhoc_exporter(&m_edhocInitiator, EDHOC_EMSK_EXPORTER_LABEL, nullptr, 0,
                                             emsk, sizeof(emsk));
                if (rc != 0)
                {
                    m_logger->err("EDHOC: initiator_edhoc_exporter failed [%d]", rc);
                    m_edhocAwaitingMessage4 = false;
                    return false;
                }

                m_usim->m_nonCurrentNsCtx->keys.kAusf = OctetString::FromArray(emsk, EDHOC_KAUSF_LEN);
                keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

                // NOTE: This is NOT an EDHOC protocol message and not required by EDHOC-PSK.
                // It is a transport/state-machine trigger for the current Open5GS integration,
                // where AUSF/AMF expects one additional UE AuthenticationResponse after relaying
                // EDHOC message_4 before proceeding with normal 5GS flow.
                nas::AuthenticationResponse resp;
                resp.eapMessage = nas::IEEapMessage{};
                resp.eapMessage->eap = std::make_unique<eap::EapNotification>(
                    eap::ECode::RESPONSE, receivedEap.id,
                    OctetString{});
                m_logger->info("EDHOC: processed message_4 and sent post-message_4 acknowledgement");
                sendNasMessage(resp);
                m_edhocAwaitingMessage4 = false;
                return true;
            }

            if (!m_edhocInProgress)
                return false;

            // Second EDHOC leg on UE: received message_2, then build/send message_3.
            if (receivedEap.rawData.length() <= 0 ||
                receivedEap.rawData.length() > static_cast<int>(sizeof(message2.content)))
            {
                m_logger->err("EDHOC: invalid message_2 length [%d]", receivedEap.rawData.length());
                m_edhocInProgress = false;
                return false;
            }

            message2.len = receivedEap.rawData.length();
            std::memcpy(message2.content, receivedEap.rawData.data(), message2.len);

            rc = initiator_parse_message_2(
                &m_edhocInitiator, &message2,
                &cR, &hasIdCredR, &idCredR, &ead2);
            if (rc != 0)
            {
                m_logger->err("EDHOC: initiator_parse_message_2 failed [%d]", rc);
                m_edhocInProgress = false;
                return false;
            }

            rc = credential_new_symmetric(&credI,
                                          EDHOC_PSK_CRED_I, sizeof(EDHOC_PSK_CRED_I));
            if (rc != 0)
            {
                m_logger->err("EDHOC: credential_new_symmetric(I) failed [%d]", rc);
                m_edhocInProgress = false;
                return false;
            }

            rc = initiator_verify_message_2(
                &m_edhocInitiator, nullptr, &credI, &m_edhocCredR);
            if (rc != 0)
            {
                m_logger->err("EDHOC: initiator_verify_message_2 failed [%d]", rc);
                m_edhocInProgress = false;
                return false;
            }

            rc = initiator_prepare_message_3(
                &m_edhocInitiator, ByReference, &ead3, &message3, &prkOut);
            m_logger->info("EDHOC: initiator_prepare_message_3 rc=%d len=%d",
                           rc, static_cast<int>(message3.len));
            if (rc != 0)
            {
                m_logger->err("EDHOC: initiator_prepare_message_3 failed [%d]", rc);
                m_edhocInProgress = false;
                return false;
            }
            if (message3.len == 0)
            {
                m_logger->err("EDHOC: initiator_prepare_message_3 produced empty message_3");
                m_edhocInProgress = false;
                return false;
            }

            nas::AuthenticationResponse resp;
            resp.eapMessage = nas::IEEapMessage{};
            resp.eapMessage->eap = std::make_unique<eap::EapNotification>(
                eap::ECode::RESPONSE, receivedEap.id,
                OctetString::FromArray(message3.content, message3.len));
            m_logger->info("EDHOC: sending message_3 in authentication response [len=%d, c_r=%u, raw_message3=1]",
                           static_cast<int>(message3.len), cR);
            sendNasMessage(resp);
            m_edhocInProgress = false;
            m_edhocAwaitingMessage4 = true;
            return true;
        }

        if (m_edhocInProgress)
            return false;

        // First EDHOC leg on UE: bootstrap marker received, generate/send message_1.
        m_logger->info("EDHOC: received dummy authentication request");
        // Since this is not AKA, the UE clears the AKA challenge/response temporary values.
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Allocate the partial native NAS security context now; populate the real K_AUSF
        // only after EDHOC completes and the exporter is available.
        m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
        m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
        m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

        m_nwConsecutiveAuthFailure = 0;
        m_timers->t3520.stop();

        rc = initiator_new(&m_edhocInitiator, PSK);
        if (rc != 0)
        {
            m_logger->err("EDHOC: initiator_new failed [%d]", rc);
            return false;
        }

        rc = credential_new_symmetric(&credI,
                                      EDHOC_PSK_CRED_I, sizeof(EDHOC_PSK_CRED_I));
        if (rc != 0)
        {
            m_logger->err("EDHOC: credential_new_symmetric(I) failed [%d]", rc);
            return false;
        }

        rc = credential_new_symmetric(&m_edhocCredR,
                                      EDHOC_PSK_CRED_R, sizeof(EDHOC_PSK_CRED_R));
        if (rc != 0)
        {
            m_logger->err("EDHOC: credential_new_symmetric(R) failed [%d]", rc);
            return false;
        }

        rc = initiator_prepare_message_1(&m_edhocInitiator, &cI, &ead1, &message1);
        if (rc != 0)
        {
            m_logger->err("EDHOC: initiator_prepare_message_1 failed [%d]", rc);
            return false;
        }
        m_edhocInProgress = true;
        m_edhocAwaitingMessage4 = false;
        m_edhocCi = cI;

        nas::AuthenticationResponse resp;
        resp.eapMessage = nas::IEEapMessage{};
        resp.eapMessage->eap = std::make_unique<eap::EapNotification>(
            eap::ECode::RESPONSE, receivedEap.id,
            OctetString::FromArray(message1.content, message1.len));
        m_logger->info("EDHOC: sending real message_1 in authentication response [len=%d, c_i=%u]",
                       static_cast<int>(message1.len), cI);
        sendNasMessage(resp);
        return true;
    };

    auto sendEapFailure = [this](std::unique_ptr<eap::Eap> &&eap) {
        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        nas::AuthenticationResponse resp;
        resp.eapMessage = nas::IEEapMessage{};
        resp.eapMessage->eap = std::move(eap);
        sendNasMessage(resp);
    };

    auto sendAuthFailure = [this](nas::EMmCause cause) {
        m_logger->err("Sending Authentication Failure with cause [%s]", nas::utils::EnumToString(cause));

        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        // Send Authentication Failure
        nas::AuthenticationFailure resp{};
        resp.mmCause.value = cause;
        sendNasMessage(resp);
    };

    // ========================== Check the received message syntactically ==========================

    if (!msg.eapMessage.has_value() || !msg.eapMessage->eap)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.eapMessage->eap->eapType == eap::EEapType::NOTIFICATION)
    {
        if (handleEdhocNotification((const eap::EapNotification &)*msg.eapMessage->eap))
            return;

        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.eapMessage->eap->eapType != eap::EEapType::EAP_AKA_PRIME)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    auto &receivedEap = (const eap::EapAkaPrime &)*msg.eapMessage->eap;

    if (receivedEap.subType != eap::ESubType::AKA_CHALLENGE)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // ================================ Check the received parameters syntactically ================================

    auto receivedRand = receivedEap.attributes.getRand();
    auto receivedMac = receivedEap.attributes.getMac();
    auto receivedAutn = receivedEap.attributes.getAutn();

    if (receivedRand.length() != 16 || receivedAutn.length() != 16 || receivedMac.length() != 16)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // =================================== Check the received KDF and KDF_INPUT ===================================

    if (receivedEap.attributes.getKdf() != 1)
    {
        m_logger->err("EAP AKA' Authentication Reject, received AT_KDF is not valid");
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
        return;
    }

    auto snn = keys::ConstructServingNetworkName(currentPlmn);

    if (receivedEap.attributes.getKdfInput() != OctetString::FromAscii(snn))
    {
        m_logger->err("EAP AKA' Authentication Reject, received AT_KDF_INPUT is not valid");

        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
        return;
    }

    // =================================== Check the received ngKSI ===================================

    if (msg.ngKSI.tsc == nas::ETypeOfSecurityContext::MAPPED_SECURITY_CONTEXT)
    {
        m_logger->err("Mapped security context not supported");
        sendAuthFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (msg.ngKSI.ksi == nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED)
    {
        m_logger->err("Invalid ngKSI value received");
        sendAuthFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if ((m_usim->m_currentNsCtx && m_usim->m_currentNsCtx->ngKsi == msg.ngKSI.ksi) ||
        (m_usim->m_nonCurrentNsCtx && m_usim->m_nonCurrentNsCtx->ngKsi == msg.ngKSI.ksi))
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();
        sendAuthFailure(nas::EMmCause::NGKSI_ALREADY_IN_USE);
        return;
    }

    // =================================== Check the received AUTN ===================================

    auto autnCheck = validateAutn(receivedRand, receivedAutn);
    m_timers->t3516.start();

    if (autnCheck == EAutnValidationRes::OK)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), receivedRand, false);
        auto sqnXorAk = OctetString::Xor(m_usim->m_sqnMng->getSqn(), milenage.ak);
        auto ckPrimeIkPrime = keys::CalculateCkPrimeIkPrime(milenage.ck, milenage.ik, snn, sqnXorAk);
        auto &ckPrime = ckPrimeIkPrime.first;
        auto &ikPrime = ckPrimeIkPrime.second;

        auto mk = keys::CalculateMk(ckPrime, ikPrime, m_base->config->supi.value());
        auto kaut = mk.subCopy(16, 32);

        // Check the received AT_MAC
        auto expectedMac = keys::CalculateMacForEapAkaPrime(kaut, receivedEap);
        if (expectedMac != receivedMac)
        {
            m_logger->err("AT_MAC failure in EAP AKA'. expected: %s received: %s", expectedMac.toHexString().c_str(),
                          receivedMac.toHexString().c_str());
            if (networkFailingTheAuthCheck(true))
                return;
            m_timers->t3520.start();

            auto eap = std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_CLIENT_ERROR);
            eap->attributes.putClientErrorCode(0);
            sendEapFailure(std::move(eap));
            return;
        }

        // Store the relevant parameters
        m_usim->m_rand = receivedRand.copy();
        m_usim->m_resStar = {};

        // Create new partial native NAS security context and continue with key derivation
        m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
        m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
        m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
        m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrime(mk);
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

        keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

        // Send response
        m_nwConsecutiveAuthFailure = 0;
        m_timers->t3520.stop();
        {
            auto *akaPrimeResponse =
                new eap::EapAkaPrime(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CHALLENGE);
            akaPrimeResponse->attributes.putRes(milenage.res);
            akaPrimeResponse->attributes.putMac(OctetString::FromSpare(16)); // Dummy mac
            akaPrimeResponse->attributes.putKdf(1);

            // Calculate and put mac value
            auto sendingMac = keys::CalculateMacForEapAkaPrime(kaut, *akaPrimeResponse);
            akaPrimeResponse->attributes.replaceMac(sendingMac);

            nas::AuthenticationResponse resp;
            resp.eapMessage = nas::IEEapMessage{};
            resp.eapMessage->eap = std::unique_ptr<eap::EapAkaPrime>(akaPrimeResponse);

            sendNasMessage(resp);
        }
    }
    else if (autnCheck == EAutnValidationRes::MAC_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
    }
    else if (autnCheck == EAutnValidationRes::SYNCHRONISATION_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();

        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), receivedRand, true);
        auto auts = keys::CalculateAuts(m_usim->m_sqnMng->getSqn(), milenage.ak_r, milenage.mac_s);

        auto eap = std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                      eap::ESubType::AKA_SYNCHRONIZATION_FAILURE);
        eap->attributes.putAuts(std::move(auts));
        sendEapFailure(std::move(eap));
    }
    else // the other case, separation bit mismatched
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();

        auto eap =
            std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CLIENT_ERROR);
        eap->attributes.putClientErrorCode(0);
        sendEapFailure(std::move(eap));
    }
}

void NasMm::receiveAuthenticationRequest5gAka(const nas::AuthenticationRequest &msg)
{
    Plmn currentPLmn = m_base->shCtx.getCurrentPlmn();
    if (!currentPLmn.hasValue())
        return;

    auto sendFailure = [this](nas::EMmCause cause, std::optional<OctetString> &&auts = std::nullopt) {
        if (cause != nas::EMmCause::SYNCH_FAILURE)
            m_logger->err("Sending Authentication Failure with cause [%s]", nas::utils::EnumToString(cause));
        else
            m_logger->debug("Sending Authentication Failure due to SQN out of range");

        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        // Send Authentication Failure
        nas::AuthenticationFailure resp{};
        resp.mmCause.value = cause;

        if (auts.has_value())
        {
            resp.authenticationFailureParameter = nas::IEAuthenticationFailureParameter{};
            resp.authenticationFailureParameter->rawData = std::move(*auts);
        }

        sendNasMessage(resp);
    };

    // ========================== Check the received parameters syntactically ==========================

    if (!msg.authParamRAND.has_value() || !msg.authParamAUTN.has_value())
    {
        sendFailure(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.authParamRAND->value.length() != 16 || msg.authParamAUTN->value.length() != 16)
    {
        sendFailure(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // =================================== Check the received ngKSI ===================================

    if (msg.ngKSI.tsc == nas::ETypeOfSecurityContext::MAPPED_SECURITY_CONTEXT)
    {
        m_logger->err("Mapped security context not supported");
        sendFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (msg.ngKSI.ksi == nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED)
    {
        m_logger->err("Invalid ngKSI value received");
        sendFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if ((m_usim->m_currentNsCtx && m_usim->m_currentNsCtx->ngKsi == msg.ngKSI.ksi) ||
        (m_usim->m_nonCurrentNsCtx && m_usim->m_nonCurrentNsCtx->ngKsi == msg.ngKSI.ksi))
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();
        sendFailure(nas::EMmCause::NGKSI_ALREADY_IN_USE);
        return;
    }

    // ============================================ Others ============================================

    auto &rand = msg.authParamRAND->value;
    auto &autn = msg.authParamAUTN->value;

    EAutnValidationRes autnCheck = EAutnValidationRes::OK;

    // If the received RAND is same with store stored RAND, bypass AUTN validation
    // NOTE: Not completely sure if this is correct and the spec meant this. But in worst case, synchronisation failure
    //  happens, and hopefully that can be restored with the normal resynchronization procedure.
    if (m_usim->m_rand != rand)
    {
        autnCheck = validateAutn(rand, autn);
        m_timers->t3516.start();
    }

    if (autnCheck == EAutnValidationRes::OK)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, false);
        auto ckIk = OctetString::Concat(milenage.ck, milenage.ik);
        auto sqnXorAk = OctetString::Xor(m_usim->m_sqnMng->getSqn(), milenage.ak);
        auto snn = keys::ConstructServingNetworkName(currentPLmn);

        // Store the relevant parameters
        m_usim->m_rand = rand.copy();
        m_usim->m_resStar = keys::CalculateResStar(ckIk, snn, rand, milenage.res);

        // Create new partial native NAS security context and continue with key derivation
        m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
        m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
        m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
        m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfFor5gAka(milenage.ck, milenage.ik, snn, sqnXorAk);
        m_usim->m_nonCurrentNsCtx->keys.kAkma = keys::CalculateAkmaKey(m_usim->m_nonCurrentNsCtx->keys.kAusf, m_base->config->supi.value());
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

        keys::DeriveKeysSeafAmf(*m_base->config, currentPLmn, *m_usim->m_nonCurrentNsCtx);

        // Send response
        m_nwConsecutiveAuthFailure = 0;
        m_timers->t3520.stop();

        nas::AuthenticationResponse resp;
        resp.authenticationResponseParameter = nas::IEAuthenticationResponseParameter{};
        resp.authenticationResponseParameter->rawData = m_usim->m_resStar.copy();

        sendNasMessage(resp);
    }
    else if (autnCheck == EAutnValidationRes::MAC_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendFailure(nas::EMmCause::MAC_FAILURE);
    }
    else if (autnCheck == EAutnValidationRes::SYNCHRONISATION_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();

        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, true);
        auto auts = keys::CalculateAuts(m_usim->m_sqnMng->getSqn(), milenage.ak_r, milenage.mac_s);
        sendFailure(nas::EMmCause::SYNCH_FAILURE, std::move(auts));
    }
    else // the other case, separation bit mismatched
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendFailure(nas::EMmCause::NON_5G_AUTHENTICATION_UNACCEPTABLE);
    }
}

void NasMm::receiveAuthenticationResult(const nas::AuthenticationResult &msg)
{
    if (msg.abba.has_value())
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba->rawData.copy();

    if (msg.eapMessage.eap->code == eap::ECode::SUCCESS)
        receiveEapSuccessMessage(*msg.eapMessage.eap);
    else if (msg.eapMessage.eap->code == eap::ECode::FAILURE)
        receiveEapFailureMessage(*msg.eapMessage.eap);
    else
        m_logger->warn("Network sent EAP with an inconvenient type in Authentication Result, ignoring EAP IE.");
}

void NasMm::receiveAuthenticationReject(const nas::AuthenticationReject &msg)
{
    m_logger->err("Authentication Reject received");

    // The RAND and RES* values stored in the ME shall be deleted and timer T3516, if running, shall be stopped
    m_usim->m_rand = {};
    m_usim->m_resStar = {};
    m_timers->t3516.stop();
    m_edhocInProgress = false;
    m_edhocAwaitingMessage4 = false;

    if (msg.eapMessage.has_value() && msg.eapMessage->eap)
    {
        if (msg.eapMessage->eap->code == eap::ECode::FAILURE)
            receiveEapFailureMessage(*msg.eapMessage->eap);
        else
            m_logger->warn("Network sent EAP with inconvenient type in AuthenticationReject, ignoring EAP IE.");
    }

    // The UE shall set the update status to 5U3 ROAMING NOT ALLOWED,
    switchUState(E5UState::U3_ROAMING_NOT_ALLOWED);
    // Delete the stored 5G-GUTI, TAI list, last visited registered TAI and ngKSI. The USIM shall be considered invalid
    // until switching off the UE or the UICC containing the USIM is removed
    m_storage->storedGuti->clear();
    m_storage->lastVisitedRegisteredTai->clear();
    m_storage->taiList->clear();
    m_usim->m_currentNsCtx = {};
    m_usim->m_nonCurrentNsCtx = {};
    m_usim->invalidate();
    // The UE shall abort any 5GMM signalling procedure, stop any of the timers T3510, T3516, T3517, T3519 or T3521 (if
    // they were running) ..
    m_timers->t3510.stop();
    m_timers->t3516.stop();
    m_timers->t3517.stop();
    m_timers->t3519.stop();
    m_timers->t3521.stop();
    // .. and enter state 5GMM-DEREGISTERED.
    switchMmState(EMmSubState::MM_DEREGISTERED_PS);
}

void NasMm::receiveEapSuccessMessage(const eap::Eap &eap)
{
    // EAP success finalizes authentication; clear any EDHOC transient state.
    m_edhocInProgress = false;
    m_edhocAwaitingMessage4 = false;
}

void NasMm::receiveEapFailureMessage(const eap::Eap &eap)
{
    m_logger->debug("Handling EAP-failure");

    // UE shall delete the partial native 5G NAS security context if any was created
    m_usim->m_nonCurrentNsCtx = {};
    m_edhocInProgress = false;
    m_edhocAwaitingMessage4 = false;
}

EAutnValidationRes NasMm::validateAutn(const OctetString &rand, const OctetString &autn)
{
    // Decode AUTN
    OctetString receivedSQNxorAK = autn.subCopy(0, 6);
    OctetString receivedAMF = autn.subCopy(6, 2);
    OctetString receivedMAC = autn.subCopy(8, 8);

    // Check the separation bit
    if (receivedAMF.get(0).bit(7) != 1)
    {
        m_logger->err("AUTN validation SEP-BIT failure. expected: 1, received: 0");
        return EAutnValidationRes::AMF_SEPARATION_BIT_FAILURE;
    }

    // Derive AK and MAC
    auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, false);
    OctetString receivedSQN = OctetString::Xor(receivedSQNxorAK, milenage.ak);

    m_logger->debug("Received SQN [%s]", receivedSQN.toHexString().c_str());
    m_logger->debug("SQN-MS [%s]", m_usim->m_sqnMng->getSqn().toHexString().c_str());

    // Verify that the received sequence number SQN is in the correct range
    bool sqn_ok = m_usim->m_sqnMng->checkSqn(receivedSQN);

    // Re-execute the milenage calculation (if case of sqn is changed with the received value)
    milenage = calculateMilenage(receivedSQN, rand, false);

    // Check MAC
    if (receivedMAC != milenage.mac_a)
    {
        m_logger->err("AUTN validation MAC mismatch. expected [%s] received [%s]", milenage.mac_a.toHexString().c_str(),
                      receivedMAC.toHexString().c_str());
        return EAutnValidationRes::MAC_FAILURE;
    }

    if(!sqn_ok)
        return EAutnValidationRes::SYNCHRONISATION_FAILURE;

    return EAutnValidationRes::OK;
}

crypto::milenage::Milenage NasMm::calculateMilenage(const OctetString &sqn, const OctetString &rand, bool dummyAmf)
{
    OctetString amf = dummyAmf ? OctetString::FromSpare(2) : m_base->config->amf.copy();

    if (m_base->config->opType == OpType::OPC)
        return crypto::milenage::Calculate(m_base->config->opC, m_base->config->key, rand, sqn, amf);

    OctetString opc = crypto::milenage::CalculateOpC(m_base->config->opC, m_base->config->key);
    return crypto::milenage::Calculate(opc, m_base->config->key, rand, sqn, amf);
}

bool NasMm::networkFailingTheAuthCheck(bool hasChance)
{
    if (hasChance && m_nwConsecutiveAuthFailure++ < 3)
        return false;

    // NOTE: Normally if we should check if the UE has an emergency. If it has, it should consider as network passed the
    //  auth check, instead of performing the actions in the following lines. But it's difficult to maintain and
    //  implement this behaviour. Therefore we would expect other solutions for an emergency case. Such as
    //  - Network initiates a Security Mode Command with IA0 and EA0
    //  - UE performs emergency registration after releasing the connection
    // END

    m_logger->err("Network failing the authentication check");

    if (m_cmState == ECmState::CM_CONNECTED)
        localReleaseConnection(true);

    m_timers->t3520.stop();
    return true;
}

} // namespace nr::ue
