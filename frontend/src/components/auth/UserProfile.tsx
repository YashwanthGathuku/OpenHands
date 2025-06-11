import React from "react";
import { useTranslation } from "react-i18next";
import {
  Dropdown,
  DropdownTrigger,
  DropdownMenu,
  DropdownItem,
} from "@nextui-org/dropdown";
import { Avatar } from "@nextui-org/avatar";
import { Button } from "@nextui-org/button";
import { FaUser, FaSignOutAlt, FaGithub } from "react-icons/fa";
import { useAuthStatus } from "#/hooks/query/use-auth-status";
import { useLogout } from "#/hooks/mutation/use-logout";

export function UserProfile() {
  const { t } = useTranslation();
  const { data: authStatus } = useAuthStatus();
  const { mutate: logout } = useLogout();

  if (!authStatus?.authenticated) {
    return null;
  }

  const handleLogout = () => {
    logout();
  };

  const displayName = authStatus.github_username || authStatus.email || "User";
  const avatarUrl = authStatus.github_username
    ? `https://github.com/${authStatus.github_username}.png`
    : undefined;

  return (
    <Dropdown placement="bottom-end">
      <DropdownTrigger>
        <Button variant="light" className="p-0 min-w-0 h-auto">
          <Avatar
            src={avatarUrl}
            name={displayName}
            size="sm"
            className="cursor-pointer"
          />
        </Button>
      </DropdownTrigger>

      <DropdownMenu aria-label="User menu">
        <DropdownItem
          key="profile"
          startContent={<FaUser />}
          className="h-14 gap-2"
        >
          <div className="flex flex-col">
            <span className="font-semibold">{displayName}</span>
            <span className="text-xs text-gray-500">{authStatus.email}</span>
          </div>
        </DropdownItem>

        {authStatus.github_username && (
          <DropdownItem
            key="github"
            startContent={<FaGithub />}
            href={`https://github.com/${authStatus.github_username}`}
            target="_blank"
          >
            {t("AUTH$VIEW_GITHUB_PROFILE")}
          </DropdownItem>
        )}

        <DropdownItem
          key="logout"
          color="danger"
          startContent={<FaSignOutAlt />}
          onClick={handleLogout}
        >
          {t("AUTH$SIGN_OUT")}
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
}
