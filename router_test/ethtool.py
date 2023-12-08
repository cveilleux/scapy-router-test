from pyroute2.ethtool import Ethtool
from pyroute2 import IPRoute
from . import logger


def get_ethtool_info(ifname):
    with IPRoute() as ipr:
        link = ipr.link("get", ifname=ifname)[0]

        ethtool = Ethtool()
        orig_ifstate = link.get_attr("IFLA_OPERSTATE")

        eth_info = eth_mode = None

        try:
            # some drivers require the iface to be up in order to fetch ethtool details
            if orig_ifstate == "DOWN":
                logger.info(
                    f"Bringing up interface {ifname} in order to inspect it with ethtool."
                )
                ipr.link("set", index=link["index"], state="up")
                brought_up = True

            eth_info = ethtool.get_link_info(ifname)
            eth_mode = ethtool.get_link_mode(ifname)

        except Exception as e:
            logger.warning(
                f"Exception occured when fetching ethtool info for interface {ifname}. This is not fatal: {e}"
            )
            pass

        ethtool.close()

    return link, eth_info, eth_mode
