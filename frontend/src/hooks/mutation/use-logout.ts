import { useMutation, useQueryClient } from "@tanstack/react-query";
import posthog from "posthog-js";
import OpenHands from "#/api/open-hands";
import { logout as authLogout } from "#/api/auth";
import { useConfig } from "../query/use-config";
import { clearLoginData } from "#/utils/local-storage";

export const useLogout = () => {
  const queryClient = useQueryClient();
  const { data: config } = useConfig();

  return useMutation({
    mutationFn: async () => {
      // Use new auth logout for multi-user mode, fallback to old method
      if (config?.APP_MODE === "MULTI_USER") {
        await authLogout();
      } else {
        await OpenHands.logout(config?.APP_MODE ?? "oss");
      }
    },
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: ["tasks"] });
      queryClient.removeQueries({ queryKey: ["settings"] });
      queryClient.removeQueries({ queryKey: ["user"] });
      queryClient.removeQueries({ queryKey: ["secrets"] });
      queryClient.removeQueries({ queryKey: ["auth"] });

      // Clear login method and last page from local storage
      if (config?.APP_MODE === "saas" || config?.APP_MODE === "MULTI_USER") {
        clearLoginData();
      }

      posthog.reset();

      // Refresh the page after all logout logic is completed
      window.location.reload();
    },
  });
};
