import React, { useState, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
} from "@nextui-org/modal";
import { Button } from "@nextui-org/button";
import { Input } from "@nextui-org/input";
import { Divider } from "@nextui-org/divider";
import { toast } from "react-toastify";
import { FaGithub } from "react-icons/fa";
import { generateOTP, verifyOTP, getGitHubAuthUrl } from "#/api/auth";

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function LoginModal({ isOpen, onClose, onSuccess }: LoginModalProps) {
  const { t } = useTranslation();
  const [step, setStep] = useState<"email" | "otp">("email");
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);

  const handleEmailSubmit = async () => {
    if (!email) {
      toast.error(t("AUTH$ENTER_EMAIL_ADDRESS"));
      return;
    }

    setLoading(true);
    try {
      await generateOTP(email);
      setStep("otp");
      toast.success(t("AUTH$OTP_SENT"));
    } catch (error) {
      toast.error(t("AUTH$FAILED_SEND_OTP"));
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async () => {
    if (!otp) {
      toast.error(t("AUTH$ENTER_OTP_CODE"));
      return;
    }

    setLoading(true);
    try {
      await verifyOTP(email, otp);
      toast.success(t("AUTH$LOGIN_SUCCESSFUL"));
      onSuccess();
      onClose();
    } catch (error) {
      toast.error(t("AUTH$INVALID_EXPIRED_OTP"));
    } finally {
      setLoading(false);
    }
  };

  const resetForm = useCallback(() => {
    setStep("email");
    setEmail("");
    setOtp("");
  }, []);

  const handleGitHubLogin = async () => {
    try {
      const { auth_url: authUrl } = await getGitHubAuthUrl();
      window.location.href = authUrl;
    } catch (error) {
      toast.error(t("AUTH$FAILED_GITHUB_LOGIN"));
    }
  };

  useEffect(() => {
    if (isOpen) {
      resetForm();
    }
  }, [isOpen, resetForm]);

  const handleClose = () => {
    resetForm();
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      placement="center"
      backdrop="blur"
    >
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">
          <h2 className="text-xl font-semibold">Sign in to OpenHands</h2>
          <p className="text-sm text-gray-500">
            {step === "email"
              ? t("AUTH$ENTER_EMAIL_FOR_CODE")
              : t("AUTH$ENTER_CODE_SENT_TO_EMAIL")}
          </p>
        </ModalHeader>

        <ModalBody>
          {step === "email" ? (
            <div className="space-y-4">
              <Input
                type="email"
                label={t("AUTH$EMAIL_ADDRESS")}
                placeholder={t("AUTH$ENTER_YOUR_EMAIL")}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleEmailSubmit()}
                autoFocus
              />

              <Divider />

              <Button
                color="default"
                variant="bordered"
                startContent={<FaGithub />}
                onClick={handleGitHubLogin}
                className="w-full"
              >
                {t("AUTH$CONTINUE_WITH_GITHUB")}
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="text-sm text-gray-600">
                {t("AUTH$CODE_SENT_TO")} <strong>{email}</strong>
              </div>

              <Input
                type="text"
                label={t("AUTH$VERIFICATION_CODE")}
                placeholder={t("AUTH$ENTER_6_DIGIT_CODE")}
                value={otp}
                onChange={(e) =>
                  setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))
                }
                onKeyPress={(e) => e.key === "Enter" && handleOtpSubmit()}
                autoFocus
              />

              <Button
                variant="light"
                size="sm"
                onClick={() => setStep("email")}
                className="text-blue-600"
              >
                {t("AUTH$USE_DIFFERENT_EMAIL")}
              </Button>
            </div>
          )}
        </ModalBody>

        <ModalFooter>
          <Button color="danger" variant="light" onClick={handleClose}>
            {t("AUTH$CANCEL")}
          </Button>

          <Button
            color="primary"
            onClick={step === "email" ? handleEmailSubmit : handleOtpSubmit}
            isLoading={loading}
          >
            {step === "email" ? t("AUTH$SEND_CODE") : t("AUTH$VERIFY_SIGN_IN")}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
