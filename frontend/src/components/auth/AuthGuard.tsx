import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nextui-org/button";
import { Card, CardBody, CardHeader } from "@nextui-org/card";
import { FaLock, FaGithub } from "react-icons/fa";
import { toast } from "react-toastify";
import { useIsAuthed } from "#/hooks/query/use-is-authed";
import { useConfig } from "#/hooks/query/use-config";
import { LoginModal } from "./LoginModal";
import { getGitHubAuthUrl } from "#/api/auth";

interface AuthGuardProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export function AuthGuard({ children, fallback }: AuthGuardProps) {
  const { t } = useTranslation();
  const { data: config } = useConfig();
  const { data: isAuthenticated, isLoading } = useIsAuthed();
  const [showLoginModal, setShowLoginModal] = useState(false);

  // Only apply auth guard for multi-user mode
  if (config?.APP_MODE !== "MULTI_USER") {
    return children;
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4" />
          <p className="text-gray-600">{t("AUTH$CHECKING_AUTHENTICATION")}</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    if (fallback) {
      return fallback;
    }

    const handleGitHubLogin = async () => {
      try {
        const { auth_url: authUrl } = await getGitHubAuthUrl();
        window.location.href = authUrl;
      } catch (error) {
        toast.error(t("AUTH$FAILED_GITHUB_LOGIN"));
      }
    };

    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <Card className="max-w-md w-full mx-4">
          <CardHeader className="flex flex-col items-center pb-0">
            <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
              <FaLock className="text-blue-600 text-2xl" />
            </div>
            <h1 className="text-2xl font-bold text-center">
              Welcome to OpenHands
            </h1>
            <p className="text-gray-600 text-center mt-2">
              {t("AUTH$SIGN_IN_TO_START")}
            </p>
          </CardHeader>

          <CardBody className="pt-6">
            <div className="space-y-4">
              <Button
                color="primary"
                size="lg"
                className="w-full"
                onClick={() => setShowLoginModal(true)}
              >
                {t("AUTH$SIGN_IN_WITH_EMAIL")}
              </Button>

              <Button
                color="default"
                variant="bordered"
                size="lg"
                startContent={<FaGithub />}
                onClick={handleGitHubLogin}
                className="w-full"
              >
                {t("AUTH$CONTINUE_WITH_GITHUB")}
              </Button>

              <div className="text-xs text-gray-500 text-center mt-4">
                {t("AUTH$TERMS_PRIVACY_NOTICE")}
              </div>
            </div>
          </CardBody>
        </Card>

        <LoginModal
          isOpen={showLoginModal}
          onClose={() => setShowLoginModal(false)}
          onSuccess={() => {
            setShowLoginModal(false);
            window.location.reload();
          }}
        />
      </div>
    );
  }

  return children;
}
