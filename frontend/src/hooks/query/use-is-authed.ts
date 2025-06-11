import { useQuery } from "@tanstack/react-query";
import axios, { AxiosError } from "axios";
import OpenHands from "#/api/open-hands";
import { getAuthStatus } from "#/api/auth";
import { useConfig } from "./use-config";
import { useIsOnTosPage } from "#/hooks/use-is-on-tos-page";

export const useIsAuthed = () => {
  const { data: config } = useConfig();
  const isOnTosPage = useIsOnTosPage();

  const appMode = config?.APP_MODE;

  return useQuery({
    queryKey: ["user", "authenticated", appMode],
    queryFn: async () => {
      try {
        // Use new auth system for multi-user mode
        if (appMode === "MULTI_USER") {
          const authStatus = await getAuthStatus();
          return authStatus.authenticated;
        }

        // Fallback to existing authentication for other modes
        await OpenHands.authenticate(appMode!);
        return true;
      } catch (error) {
        // If it's a 401 error, return false (not authenticated)
        if (axios.isAxiosError(error)) {
          const axiosError = error as AxiosError;
          if (axiosError.response?.status === 401) {
            return false;
          }
        }
        // For any other error, throw it to put the query in error state
        throw error;
      }
    },
    enabled: !!appMode && !isOnTosPage,
    staleTime: 1000 * 60 * 5, // 5 minutes
    gcTime: 1000 * 60 * 15, // 15 minutes
    retry: false,
    meta: {
      disableToast: true,
    },
  });
};
