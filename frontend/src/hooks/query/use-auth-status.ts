import { useQuery } from "@tanstack/react-query";
import { getAuthStatus } from "#/api/auth";

export const useAuthStatus = () =>
  useQuery({
    queryKey: ["auth", "status"],
    queryFn: getAuthStatus,
    staleTime: 1000 * 60 * 5, // 5 minutes
    gcTime: 1000 * 60 * 15, // 15 minutes
    retry: false,
    meta: {
      disableToast: true,
    },
  });
