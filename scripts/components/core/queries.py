# coding all QL codes and templates here

# all query follows
# * description
# * target database
# * arguments description
# * return description

QueriesDict = {
    # * query the driver structure
    # * kernel-level database
    # * 0 argument needed
    # * return [driver_name (string)]
    "getDriverType": \
    """import cpp

Struct getChildStruct(Struct st) {
    exists(Struct childst | childst = st.getAMemberVariable().getType().(Struct) | result = childst)
}

from Struct driver, Struct base
where
  base = getChildStruct+(driver) and
  base.hasName("device_driver") and
  driver.hasDefinition()
select driver.getName() as driver_name""",
    # * query the unreg function for collected drivers
    #   that is, run above query first and mark the fields to come up with this one
    # * kernel-level database
    # * 0 argument needed
    # * return [function name (string), function file (string), unreg type (string)]
    "getDriverUnreg": \
    """import cpp

private Type resolveStType(Type t) {
  if t instanceof Struct
  then result = t
  else
    if t instanceof SpecifiedType
    then result = t.(SpecifiedType).getBaseType()
    else
      if t instanceof CTypedefType
      then result = t.(CTypedefType).getBaseType()
      else result = t
}

private Type resolvePtrType(Type t) {
  if t instanceof PointerType
  then result = t.(PointerType).getBaseType()
  else
    if t instanceof SpecifiedType
    then result = resolvePtrType(t.(SpecifiedType).getBaseType())
    else
      if t instanceof CTypedefType
      then result = resolvePtrType(t.(CTypedefType).getBaseType())
      else result = t
}

abstract class UnregFunction extends Function {
  UnregFunction() { this.isDefined() and this.getFile() instanceof CFile }

  abstract string getUnregType();
}

class DunregFunction extends UnregFunction {
  string identifier;
  string driver_type;
  Field unreg_field;
  Struct driver_struct;
  Variable driver_ops;

  DunregFunction() {
    (
        driver_type = "pci" and
        driver_struct.hasName("pci_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "platform" and
        driver_struct.hasName("platform_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "ssb" and
        driver_struct.hasName("ssb_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "bcma" and
        driver_struct.hasName("bcma_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "pnp" and
        driver_struct.hasName("pnp_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "pnp_card" and
        driver_struct.hasName("pnp_card_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "i2c" and
        driver_struct.hasName("i2c_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "spi" and
        driver_struct.hasName("spi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "virtio" and
        driver_struct.hasName("virtio_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "nd_device" and
        driver_struct.hasName("nd_device_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "pcmcia" and
        driver_struct.hasName("pcmcia_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "auxiliary" and
        driver_struct.hasName("auxiliary_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "isa" and
        driver_struct.hasName("isa_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "phy" and
        driver_struct.hasName("phy_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "i3c" and
        driver_struct.hasName("i3c_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "sdw" and
        driver_struct.hasName("sdw_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "slim" and
        driver_struct.hasName("slim_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "spmi" and
        driver_struct.hasName("spmi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "xenbus" and
        driver_struct.hasName("xenbus_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "sdio" and
        driver_struct.hasName("sdio_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "serdev_device" and
        driver_struct.hasName("serdev_device_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "fsl_mc" and
        driver_struct.hasName("fsl_mc_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mhi" and
        driver_struct.hasName("mhi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "scmi" and
        driver_struct.hasName("scmi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "dax_device" and
        driver_struct.hasName("dax_device_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "pci_epf" and
        driver_struct.hasName("pci_epf_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "fw" and
        driver_struct.hasName("fw_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "coreboot" and
        driver_struct.hasName("coreboot_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "dfl" and
        driver_struct.hasName("dfl_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mcb" and
        driver_struct.hasName("mcb_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "siox" and
        driver_struct.hasName("siox_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mipi_dsi" and
        driver_struct.hasName("mipi_dsi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mdev" and
        driver_struct.hasName("mdev_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "amba" and
        driver_struct.hasName("amba_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "hid" and
        driver_struct.hasName("hid_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "hv" and
        driver_struct.hasName("hv_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "ishtp_cl" and
        driver_struct.hasName("ishtp_cl_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "intel_th" and
        driver_struct.hasName("intel_th_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "ide" and
        driver_struct.hasName("ide_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "bttv_sub" and
        driver_struct.hasName("bttv_sub_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "rpmsg" and
        driver_struct.hasName("rpmsg_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "memstick" and
        driver_struct.hasName("memstick_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "tifm" and
        driver_struct.hasName("tifm_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mei_cl" and
        driver_struct.hasName("mei_cl_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mmc" and
        driver_struct.hasName("mmc_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "spi_mem" and
        driver_struct.hasName("spi_mem_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "mdio" and
        driver_struct.hasName("mdio_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "tb_service" and
        driver_struct.hasName("tb_service_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "pcie_port_service" and
        driver_struct.hasName("pcie_port_service_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "ulpi" and
        driver_struct.hasName("ulpi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "wmi" and
        driver_struct.hasName("wmi_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "rio" and
        driver_struct.hasName("rio_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "apr" and
        driver_struct.hasName("apr_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "anybuss_client" and
        driver_struct.hasName("anybuss_client_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "gbphy" and
        driver_struct.hasName("gbphy_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "visor" and
        driver_struct.hasName("visor_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "vme" and
        driver_struct.hasName("vme_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "typec_altmode" and
        driver_struct.hasName("typec_altmode_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "vdpa" and
        driver_struct.hasName("vdpa_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "hdac" and
        driver_struct.hasName("hdac_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "ac97_codec" and
        driver_struct.hasName("ac97_codec_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "acpi_device" and
        driver_struct.hasName("acpi_device_ops") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "gameport" and
        driver_struct.hasName("gameport_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "greybus" and
        driver_struct.hasName("greybus_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "usb_composite" and
        driver_struct.hasName("usb_composite_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "usb_serial" and
        driver_struct.hasName("usb_serial_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "usb" and
        driver_struct.hasName("usb_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "serio" and
        driver_struct.hasName("serio_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "usb_device" and
        driver_struct.hasName("usb_device_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "usb_gadget" and
        driver_struct.hasName("usb_gadget_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("disconnect")
        or
        driver_type = "parport" and
        driver_struct.hasName("parport_driver") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("detach")
        or
        driver_type = "tty_ldisc" and
        driver_struct.hasName("tty_ldisc_ops") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("close")
        or
        driver_type = "ntb_transport_client" and
        driver_struct.hasName("ntb_transport_client") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "rmi_function_handler" and
        driver_struct.hasName("rmi_function_handler") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("remove")
        or
        driver_type = "saa7146_extension" and
        driver_struct.hasName("saa7146_extension") and
        resolveStType(driver_ops.getType()) = driver_struct and
        unreg_field = driver_struct.getAField() and
        unreg_field.hasName("detach")
    ) and
    identifier = driver_ops.getName() and
    (
        this =
        driver_ops
            .getInitializer()
            .getExpr()
            .(ClassAggregateLiteral)
            .getFieldExpr(unreg_field)
            .(FunctionAccess)
            .getTarget()
        or
        // eliminate false negative
        this = 
        driver_ops
            .getInitializer()
            .getExpr()
            .(ClassAggregateLiteral)
            .getFieldExpr(unreg_field)
            .(AddressOfExpr)
            .getOperand()
            .(FunctionAccess)
            .getTarget()
    )
  }

  override string getUnregType() { result = "driver" }
}

class InDunregFunction extends UnregFunction {
  string identifier;
  string driver_type;
  Field ops_field;
  Field unreg_field;
  Struct driver_struct;
  Struct ops_struct;
  Variable driver_wrap;

  InDunregFunction() {
    ((
        driver_type = "acpi" and
        driver_struct.hasName("acpi_driver") and
        ops_struct.hasName("acpi_device_ops") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("ops") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "eisa" and
        driver_struct.hasName("eisa_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "fsi" and
        driver_struct.hasName("fsi_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("drv") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "bcm2835_audio" and
        driver_struct.hasName("bcm2835_audio_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "drm_i2c_encoder" and
        driver_struct.hasName("drm_i2c_encoder_driver") and
        ops_struct.hasName("i2c_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("i2c_driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "drv_priv" and
        driver_struct.hasName("drv_priv") and
        ops_struct.hasName("usb_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("r871xu_drv") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("disconnect")
    ) or (
        driver_type = "hda_codec" and
        driver_struct.hasName("hda_codec_driver") and
        ops_struct.hasName("hdac_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("core") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "hsi_client" and
        driver_struct.hasName("hsi_client_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "idxd_device" and
        driver_struct.hasName("idxd_device_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("drv") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "ipack" and
        driver_struct.hasName("ipack_driver") and
        ops_struct.hasName("ipack_driver_ops") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("ops") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "moxtet" and
        driver_struct.hasName("moxtet_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "ntb_client" and
        driver_struct.hasName("ntb_client") and
        ops_struct.hasName("ntb_client_ops") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("ops") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "radio_isa" and
        driver_struct.hasName("radio_isa_driver") and
        ops_struct.hasName("isa_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "rmi" and
        driver_struct.hasName("rmi_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "scsi" and
        driver_struct.hasName("scsi_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("gendrv") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "snd_seq" and
        driver_struct.hasName("snd_seq_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "tc" and
        driver_struct.hasName("tc_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "tee_client" and
        driver_struct.hasName("tee_client_driver") and
        ops_struct.hasName("device_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("remove")
    ) or (
        driver_type = "uvc" and
        driver_struct.hasName("uvc_driver") and
        ops_struct.hasName("usb_driver") and
        resolveStType(driver_wrap.getType()) = driver_struct and
        ops_field = driver_struct.getAField() and
        ops_field.hasName("driver") and
        unreg_field = ops_struct.getAField() and
        unreg_field.hasName("disconnect")
    )) and
    identifier = driver_wrap.getName() and
    (
        this =
        driver_wrap
            .getInitializer()
            .getExpr()
            .(ClassAggregateLiteral)
            .getFieldExpr(ops_field)
            .(ClassAggregateLiteral)
            .getFieldExpr(unreg_field)
            .(FunctionAccess)
            .getTarget()
        or
        this =
        driver_wrap
            .getInitializer()
            .getExpr()
            .(ClassAggregateLiteral)
            .getFieldExpr(ops_field)
            .(ClassAggregateLiteral)
            .getFieldExpr(unreg_field)
            .(AddressOfExpr)
            .getOperand()
            .(FunctionAccess)
            .getTarget()
    )
  }

  override string getUnregType() { result = "driver" }
}

from UnregFunction f
select f, f.(Function).getFile().getRelativePath(), f.getUnregType()""",
    # * query the unreg function for upper layers
    #   with the character-based herustics discussed in paper
    # * kernel-level database
    # * 0 argument needed
    # * return [function name (string), function file (string), unreg type (string)]
    "getUpperUnreg": \
    """import cpp

private Type resolveStType(Type t) {
  if t instanceof Struct
  then result = t
  else
    if t instanceof SpecifiedType
    then result = t.(SpecifiedType).getBaseType()
    else
      if t instanceof CTypedefType
      then result = t.(CTypedefType).getBaseType()
      else result = t
}

private Type resolvePtrType(Type t) {
  if t instanceof PointerType
  then result = t.(PointerType).getBaseType()
  else
    if t instanceof SpecifiedType
    then result = resolvePtrType(t.(SpecifiedType).getBaseType())
    else
      if t instanceof CTypedefType
      then result = resolvePtrType(t.(CTypedefType).getBaseType())
      else result = t
}

abstract class UnregFunction extends Function {
  UnregFunction() { this.isDefined() and this.getFile() instanceof CFile }

  abstract string getUnregType();
}

class HunregFunction extends UnregFunction {
  Function regfunc;
  string s1;
  string s2;
  string s3;
  string s4;

  HunregFunction() {
    regfunc.getFile() = this.getFile() and
    (
      s1 = regfunc.getName().regexpCapture("^(\\\\w*)_register_(\\\\w*dev[^_]*)$", 1) and
      s2 = regfunc.getName().regexpCapture("^(\\\\w*)_register_(\\\\w*dev[^_]*)$", 2) and
      s3 = this.getName().regexpCapture("^(\\\\w*)_(de|un)register_(\\\\w*dev[^_]*)$", 1) and
      s4 = this.getName().regexpCapture("^(\\\\w*)_(de|un)register_(\\\\w*dev[^_]*)$", 3) and
      s1 = s3 and
      s2 = s4
      or
      s1 = regfunc.getName().regexpCapture("^register_(\\\\w*dev[^_]*)$", 1) and
      s4 = this.getName().regexpCapture("^(de|un)register_(\\\\w*dev[^_]*)$", 2) and
      s2 = "" and s3 = "" and
      s1 = s4 and
      s2 = s3
    ) and
    this.getNumberOfParameters() = 1 and
    this.getType().toString().matches("void") and
    resolvePtrType(this.getParameter(0).getType()).getName().matches("%dev%") and
    exists(MacroInvocation ma |
      ma.toString().matches("%EXPORT_SYMBOL%") and
      ma.getExpandedArgument(0) = this.getName()
    )
  }

  override string getUnregType() { result = "heuristics" }
}

class NunregFunction extends UnregFunction {
  NunregFunction() {
    exists(FunctionAccess fa, SwitchCase sw |
      fa.getTarget() = this and
      this.getParameter(0).getType().(PointerType).getBaseType().(Struct).hasName("notifier_block") and
      this.getParameter(1).getType().hasName("unsigned long") and
      this.getParameter(2).getType().hasName("void *") and
      this.getFile().getRelativePath().matches("%/net/%") and
      not getFile().getRelativePath().matches("%/drivers/%") and
      // make sure driven by switch case
      sw.getEnclosingFunction() = this
    )
  }

  override string getUnregType() { result = "net_notifier" }
}

from UnregFunction f
select f, f.(Function).getFile().getRelativePath(), f.getUnregType()""",
    # * query the unreg function for upper layers based on a given unreg
    #   also with the character-based herustics discussed in paper
    # * layer-level database
    # * 2 argument needed
    #   * funcname: name of the given unreg funciton
    #   * funcfile: relative file of the given unreg function
    # * return [function name (string)]
    #   * ignore file here because this file is not defined here
    "UnregUpperName": \
    """import cpp
                        
Function directCallParent(Function dst) {{
  result = dst.getACallToThisFunction().getEnclosingFunction()
}}

from Function unreg, FunctionCall upper_unreg_call, Function upper_unreg
where
    unreg.getName().matches("{funcname}") and 
    unreg.getFile().getRelativePath().matches("{funcfile}") and
    not upper_unreg.isDefined() and
    upper_unreg.getNumberOfParameters() = 1 and
    upper_unreg.getType().toString().matches("void") and
    upper_unreg.getName().matches(["%unregister%", "%deregister%"]) and
    upper_unreg_call.getTarget() = upper_unreg and
    unreg = directCallParent*(upper_unreg)
select upper_unreg.getName()""",
    # * get the name + file (meta) for a given constrants name
    # * kernel-level database
    # * 1 argument needed
    #   * constraints: name of the given funciton
    # * return [function name (string), function file (string)]
    "TranslateName2Meta": \
    """import cpp
from Function target
where
    target.getName().matches({constraints}) and
    target.getFile() instanceof CFile
select target.getName(), target.getFile().getRelativePath()""",
    # * <template> get the callsites of given function
    # * kernel-level database
    # 2 argument needed
    #   * %s: name of the given function
    #   * %s: relative file of the given functino
    # * return [tag, callsite file (string), callsite startofline (int)]
    "GetCallSites": \
    """import cpp

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

from int tag, Function want, FunctionCall fc
where %s
select tag, deriveLocation(fc.getLocation())
===
tag = %d and %s
===
want.getName().matches(%s) and 
want.getFile().getRelativePath().matches(%s) and
fc.getTarget() = want""",
    # * <common> common helper code for deref related queries
    "DerefCommon": \
    """import cpp
    
predicate resolveToFptrType(Type t)
{
  t instanceof FunctionPointerType or
  (
    t instanceof CTypedefType and
    t.(CTypedefType).getBaseType() instanceof FunctionPointerType
  )
  or
  (
    t instanceof PointerType and
    t.(PointerType).getBaseType().(CTypedefType).getBaseType() instanceof RoutineType
  )
} 

class StructWithFunctionPtr extends Struct {
  Field functionPtrField;

  StructWithFunctionPtr() {
    functionPtrField = this.getAField() and
    resolveToFptrType(functionPtrField.getType())
  }

  Field getFunctionPtrField() { result = functionPtrField }
}

private Type resolveStType(Type t) {
  if t instanceof Struct
  then result = t
  else
    if t instanceof SpecifiedType
    then result = t.(SpecifiedType).getBaseType()
    else
      if t instanceof CTypedefType
      then result = t.(CTypedefType).getBaseType()
      else result = t
}

class StructWithFunctionPtrImmediate extends StructWithFunctionPtr {
  StructWithFunctionPtrImmediate() {
    // driver structure is far away from our expectation, discard them
    not this.hasName([
      "usb_serial_driver", "rio_driver", "i2c_driver", "ishtp_cl_driver", "mei_cl_driver", "sdw_driver", "mcb_driver", 
      "mdio_driver", "serio_driver", "rpmsg_driver", "ssb_driver", "mdev_driver", "apr_driver", "anybuss_client_driver", 
      "hdac_driver", "tty_ldisc_ops", "amba_driver", "gameport_driver", "greybus_driver", "isa_driver", "mhi_driver", 
      "intel_th_driver", "vme_driver", "nd_device_driver", "platform_driver", "pnp_driver", "pcmcia_driver", "usb_driver", 
      "hv_driver", "mipi_dsi_driver", "spi_mem_driver", "hid_driver", "dax_device_driver", "mmc_driver", "dfl_driver", 
      "tb_service_driver", "visor_driver", "usb_composite_driver", "scmi_driver", "pnp_card_driver", "i3c_driver", 
      "coreboot_driver", "virtio_driver", "serdev_device_driver", "spmi_driver", "typec_altmode_driver", "usb_device_driver", 
      "pcie_port_service_driver", "ulpi_driver", "vdpa_driver", "siox_driver", "wmi_driver", "tifm_driver", "memstick_driver", 
      "spi_driver", "ide_driver", "bttv_sub_driver", "ac97_codec_driver", "auxiliary_driver", "slim_driver", "bcma_driver", 
      "pci_driver", "parport_driver", "phy_driver", "acpi_device_ops", "usb_gadget_driver", "sdio_driver", "pci_epf_driver", 
      "fw_driver", "gbphy_driver", "fsl_mc_driver", "xenbus_driver",
    ])
  }
}

class StructWithFunctionPtrGvar extends StructWithFunctionPtrImmediate {
  GlobalVariable v;
  Initializer i;

  StructWithFunctionPtrGvar() { this = resolveStType(v.getType()) and i = v.getInitializer() }

  Variable getVariable() { result = v }

  Initializer getVInitializer() { result = i }
}

class StructWithFunctionPtrInFunc extends StructWithFunctionPtrImmediate {
  Function f;
  PointerFieldAccess pfa;

  StructWithFunctionPtrInFunc() {
    pfa.getTarget() = this.getFunctionPtrField() and pfa.getEnclosingFunction() = f
  }

  Function getFunction() { result = f }

  PointerFieldAccess getPointerFieldAccess() { result = pfa }
}

class StructWithFunctionPtrInFunc2 extends StructWithFunctionPtrImmediate {
  Function f;
  ValueFieldAccess vfa;

  StructWithFunctionPtrInFunc2() {
    vfa.getTarget() = this.getFunctionPtrField() and vfa.getEnclosingFunction() = f
  }

  Function getFunction() { result = f }

  ValueFieldAccess getValueFieldAccess() { result = vfa }
}

// TODO: genl_small_ops array and genl_ops array
""",
    # * get the global structure that initialized with pointers
    # * layer-level database
    # * 1 argument needed
    #   * constraints: layer keyword for matching (always directory)
    # * return [structure name (string), structure file (string),
    #           varname (string), varfile(string),
    #           fieldname (string),
    #           funcname (string), funcfile (string)]
    "DerefGVar1": \
    """from StructWithFunctionPtrGvar st, GlobalVariable v, Initializer i, Field field, Function f
where
 field = st.getFunctionPtrField() and
 v = st.getVariable() and
 v.getFile().getRelativePath().matches("%%%s%%") and
 v.getFile() instanceof CFile and
 i = v.getInitializer() and
 (
     f = i.getExpr().(ClassAggregateLiteral).getFieldExpr(field).(FunctionAccess).getTarget() or
     f = i.getExpr().(ClassAggregateLiteral).getFieldExpr(field).(AddressOfExpr).getOperand().(FunctionAccess).getTarget()
 ) and
 f.getFile() instanceof CFile
select st, st.getFile().getRelativePath(), v, v.getFile().getRelativePath(), field, f, f.getFile().getRelativePath()""",
    # * get the global structure that initialized with pointers by ClassAggregateLiteral
    # * layer-level database
    # * 1 argument needed
    #   * constraints: layer keyword for matching (always directory)
    # * return [structure name (string), structure file (string),
    #           fieldname (string),
    #           funcname (string), funcfile (string)]
    "DerefGVar2": \
    """from StructWithFunctionPtrImmediate st, Field field, ClassAggregateLiteral expr, Function func
where
 field = st.getFunctionPtrField() and
 (
    func = expr.getFieldExpr(field).(FunctionAccess).getTarget() or
    func = expr.getFieldExpr(field).(AddressOfExpr).getOperand().(FunctionAccess).getTarget()
 ) and
 func.getFile() instanceof CFile and
 expr.getFile().getRelativePath().matches("%%%s%%") and
 not exists(Function encloser | encloser = expr.getEnclosingFunction())
select st, st.getFile().getRelativePath(), field, func, func.getFile().getRelativePath()""",
    # * get the initialized function pointer dynamic in functions
    # * kernel-level database
    # * 1 argument needed
    #   * constraints: layer keyword for matching (always directory)
    # * return [structure name (string), structure file (string),
    #           assignment-inside function name (string), fieldname (string)
    #           funcname (string), funcfile (string)]
    "DerefDyn1": \
    """from StructWithFunctionPtrInFunc st, PointerFieldAccess pfa, AssignExpr ass, Function f
where
  pfa = st.getPointerFieldAccess() and
  pfa = ass.getLValue() and
  ass.getFile().getRelativePath().matches("%%%s%%") and
  (
    f = ass.getRValue().(FunctionAccess).getTarget() or
    f = ass.getRValue().(AddressOfExpr).getOperand().(FunctionAccess).getTarget()
  )
select st, st.getFile().getRelativePath(), ass.getEnclosingFunction(), pfa.getTarget(), f, f.getFile().getRelativePath()""",
    # * get the initialized function pointer dynamic in functions (with variable access)
    # * layer-level database
    # * 1 argument needed
    #   * constraints: layer keyword for matching (always directory)
    # * return [structure name (string), structure file (string),
    #           assignment-inside function name (string), fieldname (string)
    #           funcname (string), funcfile (string)]
    "DerefDyn2": \
    """from StructWithFunctionPtrInFunc2 st, ValueFieldAccess vfa, AssignExpr ass, Function f
where
  vfa = st.getValueFieldAccess() and
  vfa = ass.getLValue() and
  ass.getFile().getRelativePath().matches("%%%s%%") and
  (
      f = ass.getRValue().(FunctionAccess).getTarget() or
      f = ass.getRValue().(AddressOfExpr).getOperand().(FunctionAccess).getTarget()
  )
select st, st.getFile().getRelativePath(), ass.getEnclosingFunction(), vfa.getTarget(), f, f.getFile().getRelativePath()""",
    # * <template> get the indirect call via field pointers
    # * layer-level database
    # 2 argument needed
    #   * %s: name of the given structure
    #   * %s: relative file of the given structure
    # * return [tag, struct name (string), struct file (string)]
    "GetStFieldCallSound": """import cpp

predicate resolveToFptrType(Type t)
{
  t instanceof FunctionPointerType or
  (
    t instanceof CTypedefType and
    t.(CTypedefType).getBaseType() instanceof FunctionPointerType
  )
  or
  (
    t instanceof PointerType and
    t.(PointerType).getBaseType().(CTypedefType).getBaseType() instanceof RoutineType
  )
} 

class StructWithFunctionPtr extends Struct {
  Field functionPtrField;

  StructWithFunctionPtr() {
    functionPtrField = this.getAField() and
    resolveToFptrType(functionPtrField.getType())
  }

  Field getFunctionPtrField() { result = functionPtrField }
}

from int tag, StructWithFunctionPtr st
where %s
select tag, st, st.getFile().getRelativePath()
===
tag = %d and %s
===
st.hasName(%s) and
st.getFile()
    .getRelativePath()
    .matches(%s) and
exists(
    Field field, File file |
    field = st.getFunctionPtrField() and
    (
        exists(PointerFieldAccess pfa | field = pfa.getTarget() | file = pfa.getFile()) or
        exists(ValueFieldAccess vfa | field = vfa.getTarget() | file = vfa.getFile())
    ) and
    file instanceof CFile
)""",
    # * get the function declarations in headers
    # * layer-level database
    # 1 argument needed
    #   * func_name: name of the given function
    # * return [declara, declara file]
    "GetFuncDeclara": \
    """import cpp
from Function func, DeclarationEntry de
where
  func.hasName({}) and
  de = func.getADeclarationEntry() and
  not de = func.getDefinition() and
  de.getFile() instanceof HeaderFile
select de, de.getFile().getRelativePath()""",
    # * <template>
    # * layer-level database
    # 3 argument needed
    #   * %s: name of the given structure
    #   * %s: relative file of the given structure
    #   * %s: field name
    # * return [tag, struct name (string), struct file (string), struct field (string)]
    "GetStFieldCall": \
    """import cpp

from int tag, Struct st, Field field, File file
where %s
select tag, st, st.getFile().getRelativePath(), field
===
tag = %d and %s
===
st.hasName(%s) and
st.getFile()
    .getRelativePath()
    .matches(%s) and
field = st.getAField() and
field.hasName(%s) and
(
    exists(PointerFieldAccess pfa | field = pfa.getTarget() | file = pfa.getFile()) or
    exists(ValueFieldAccess vfa | field = vfa.getTarget() | file = vfa.getFile())
) and
file instanceof CFile""",
    # * get netlink ops functinos
    # * layer-level database
    # * 1 argument needed
    #   * %s: relative keyword
    # * return [structname (string), structfile (string),
    #           filedname (string)
    #           funcname (string), funcfile (string)]
    "GetNetlinkOps": \
    """import cpp

predicate resolveToFptrType(Type t)
{
  t instanceof FunctionPointerType or
  (
    t instanceof CTypedefType and
    t.(CTypedefType).getBaseType() instanceof FunctionPointerType
  )
  or
  (
    t instanceof PointerType and
    t.(PointerType).getBaseType().(CTypedefType).getBaseType() instanceof RoutineType
  )
}

class StructWithFunctionPtrSpecial extends Struct {
  Field functionPtrField;

  StructWithFunctionPtrSpecial() {
    functionPtrField = this.getAField() and
    resolveToFptrType(functionPtrField.getType())
  }

  Field getFunctionPtrField() { result = functionPtrField }
}

from StructWithFunctionPtrSpecial st, Field field, ClassAggregateLiteral expr, Function func
where
  st.hasName(["genl_small_ops", "genl_ops"]) and
  field = st.getFunctionPtrField() and
  func = expr.getFieldExpr(field).(FunctionAccess).getTarget() and
  func.getFile() instanceof CFile and
  expr.getFile().getRelativePath().matches("%%%s%%")
select st, st.getFile().getRelativePath(), field, func, func.getFile().getRelativePath()""",

    # * get other ops functinos
    # * layer-level database
    # * 1 argument needed
    #   * %s: relative keyword
    # * return [structname (string), structfile (string),
    #           filedname (string)
    #           funcname (string), funcfile (string)]
    "GetPreGVarOps": \
    """import cpp

predicate resolveToFptrType(Type t)
{
  t instanceof FunctionPointerType or
  (
    t instanceof CTypedefType and
    t.(CTypedefType).getBaseType() instanceof FunctionPointerType
  )
  or
  (
    t instanceof PointerType and
    t.(PointerType).getBaseType().(CTypedefType).getBaseType() instanceof RoutineType
  )
} 
private Type resolveStType(Type t) {
  if t instanceof Struct
  then result = t
  else
    if t instanceof SpecifiedType
    then result = t.(SpecifiedType).getBaseType()
    else
      if t instanceof CTypedefType
      then result = t.(CTypedefType).getBaseType()
      else result = t
}

class StructWithFunctionPtr extends Struct {
  Field functionPtrField;

  StructWithFunctionPtr() {
    functionPtrField = this.getAField() and
    resolveToFptrType(functionPtrField.getType())
  }

  Field getFunctionPtrField() { result = functionPtrField }
}

class StructWithFunctionPre extends StructWithFunctionPtr {
  StructWithFunctionPre() {
    this.hasName([
        "file_operations",
        // TODO more
    ])
  }
}

class StructWithFunctionPtrGvar extends StructWithFunctionPre {
  GlobalVariable v;
  Initializer i;

  StructWithFunctionPtrGvar() { this = resolveStType(v.getType()) and i = v.getInitializer() }

  Variable getVariable() { result = v }

  Initializer getVInitializer() { result = i }
}

from StructWithFunctionPtrGvar st, GlobalVariable v, Initializer i, Field field, Function f
where
 field = st.getFunctionPtrField() and
 v = st.getVariable() and
 v.getFile().getRelativePath().matches("%%%s%%") and
 v.getFile() instanceof CFile and
 i = v.getInitializer() and
 (
     f = i.getExpr().(ClassAggregateLiteral).getFieldExpr(field).(FunctionAccess).getTarget() or
     f = i.getExpr().(ClassAggregateLiteral).getFieldExpr(field).(AddressOfExpr).getOperand().(FunctionAccess).getTarget()
 ) and
 f.getFile() instanceof CFile
select st, st.getFile().getRelativePath(), field, f, f.getFile().getRelativePath()""",
    # * <common> common code for kernel heap actions
    "HeapCommon": \
    """import cpp
import semmle.code.cpp.pointsto.PointsTo
import semmle.code.cpp.controlflow.StackVariableReachability
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.ControlFlowGraph

/**
 * A deallocation function such as `kfree`.
 */
class KStandardDeallocationFunction extends DeallocationFunction {
  int freedArg;

  KStandardDeallocationFunction() {
      hasName([
          "kfree", // kfree(const void *);
          "kfree_sensitive",  // kfree_sensitive(const void *)
          "kfree_const", // void kfree_const(const void *x)
          "kvfree"    // void kvfree(const void *addr)
          // "kfree_rcu" macro here
      ]) and
      freedArg = 0
      or
      hasName([
          "kmem_cache_free"  // kmem_cache_free(struct kmem_cache *, void *)
      ]) and
      freedArg = 1
      or
      // export function need to be modeled
      hasName([
          "kfree_skb",
          "destroy_workqueue",
          "rfkill_destroy",
          "crypto_free_shash"
          // TODO: more?
      ]) and
      freedArg = 0
  }

  override int getFreedArg() { result = freedArg }
}

/**
 * An allocation expression that is a `kmalloc` expression.
 */
private class KMallocAllocationFunction extends AllocationFunction {
  int sizeArg;

  /* index size argument */
  // we don't really care about the size & flags for now
  KMallocAllocationFunction() {
    hasName([
        "kmalloc", // kmalloc(size_t size, gfp_t flags)
        "kmalloc_order", // kmalloc_order(size_t size, gfp_t flags, unsigned int order)
        "kmalloc_order_trace", // kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
        "__kmalloc", // __kmalloc(size_t size, gfp_t flags)
        "kmalloc_large", // kmalloc_large(size_t size, gfp_t flags)
        "kzalloc", // kzalloc(size_t size, gfp_t flags)
        "kmalloc_node", // kmalloc_node(size_t size, gfp_t flags, int node)
        "__kmalloc_node", // __kmalloc_node(size_t size, gfp_t flags, int node)
        "kzalloc_node" // kzalloc_node(size_t size, gfp_t flags, int node)
      ]) and
    sizeArg = 0
  }

  override int getSizeArg() { result = sizeArg }
}

/**
 * An allocation from `vmalloc` area
 */
private class VMallocAllocationFunction extends AllocationFunction {
  int sizeArg;

  VMallocAllocationFunction() {
    hasName([
        "vmalloc", // vmalloc(unsigned long size)
        "vmalloc_node", // vmalloc_node(unsigned long size, int node)
        "vzalloc", // vzalloc(unsigned long size)
        "vzalloc_node", // vzalloc_node(unsigned long size, int node)
        "vmalloc_user", // vmalloc_user(unsigned long size)
        "__vmalloc" // __vmalloc(unsigned long size, gfp_t gfp_mask)
      ]) and
    sizeArg = 1
  }

  override int getSizeArg() { result = sizeArg }
}

/**
 * An allocation function requires no size argument but need cache
 * argument
 */
private class KCacheAllocationFunction extends AllocationFunction {
	/* TODO: add helper to find target? */
	int sizeArg;

	KCacheAllocationFunction() {
		hasName([
			"kmem_cache_alloc",	// kmem_cache_alloc(struct kmem_cache *, gfp_t flags)
			"kmem_cache_zalloc",	// kmem_cache_zalloc(struct kmem_cache *, gfp_t flags)
			"kmem_cache_alloc_trace",	// kmem_cache_alloc_trace(struct kmem_cache *, gfp_t, size_t)
			"kmem_cache_alloc_node_trace"	// kmem_cache_alloc_node_trace(struct kmem_cache *, gfp_t, size_t)
		]) and
		sizeArg = -1
	}

	override int getSizeArg() { result = sizeArg }
}

/**
 * An allocation function for array elements
 */
private class KArrayAllocationFunction extends AllocationFunction {
	int sizeArg;
	int nArg;

	KArrayAllocationFunction() {
		hasName([
			"kmalloc_array",
			"kmalloc_array_node"
		]) and
		sizeArg = 1 and nArg = 0
	}

	override int getSizeArg() { result = sizeArg }
	int getnArg() {result = nArg }
}

/* TODO: other wrapper */
private class KWrapAllocationFunction extends AllocationFunction {
  // size are unnecessary

  /* try out best */
  KWrapAllocationFunction() {
    hasName([
      "alloc_workqueue", // find these wrapper with ql
      "alloc_skb",
      "skb_clone",
      "bt_skb_alloc",
      "bpf_map_kzalloc",
      "fasync_alloc",
      "alloc_ucounts",
      "vm_area_alloc",
      "bpf_map_offload_map_alloc",
      "bpf_prog_array_alloc",
      "bitmap_alloc",
      "alloc_msi_entry",
      "pci_vpd_alloc",
      "amd_uncore_alloc",
      "allocate_fake_cpuc",
      "kcalloc",
      "allocate_shared_regs",
      "allocate_excl_cntrs",
      "platform_device_alloc",
      "alloc_apic_chip_data",
      "alloc_workqueue_attrs",
      "alloc_pid",
      "key_alloc",
      "alloc_uid",
      "mm_alloc",
      "alloc_sched_domains",
      "mempool_kmalloc",
      "bio_kmalloc",
      "elevator_alloc",
      "cdev_alloc",
      "__skb_ext_alloc",
      "alloc_skb_for_msg",
      "alloc_skb_with_frags",
      "alloc_ldt_struct",
      "alloc_ldt_struct",
      "resv_map_alloc",
      "resv_map_alloc",
      "alloc_pci_root_info",
      "pci_mmconfig_alloc",
      "bvec_alloc",
      "bdi_alloc",
      "kyber_queue_data_alloc",
      "allocate_partitions",
      "allocate_partitions",
      "alloc_read_gpt_header",
      "alloc_read_gpt_entries",
      "__acomp_request_alloc",
      "aead_request_alloc",
      "ahash_request_alloc",
      "crypto_larval_alloc",
      "asymmetric_restriction_alloc",
      "akcipher_request_alloc",
      "skcipher_request_alloc",
      "kpp_request_alloc",
      "aead_geniv_alloc",
      "jent_zalloc",
      "acpi_ec_alloc",
      "scsi_host_alloc",
      "scsi_host_alloc",
      "sdev_evt_alloc",
      "ata_host_alloc",
      "ata_port_alloc",
      "alloc_fw_cache_entry",
      "regcache_rbtree_node_alloc",
      "regcache_rbtree_node_alloc",
      "regmap_field_alloc",
      "software_node_alloc",
      "flow_block_cb_alloc",
      "flow_rule_alloc",
      "alloc_diag_urb",
      "alloc_ctrl_urb",
      "alloc_clk",
      "vclkdev_alloc",
      "bpf_prog_realloc",
      "cpufreq_policy_alloc",
      "od_alloc",
      "dma_resv_list_alloc",
      "sync_file_alloc",
      "drm_dev_alloc",
      "__devm_drm_dev_alloc",
      "drm_atomic_state_alloc",
      "drm_file_alloc",
      "alloc_apertures",
      "drm_sysfs_minor_alloc",
      "mipi_dsi_device_alloc",
      "dma_fence_chain_alloc",
      "intel_connector_alloc",
      "intel_plane_alloc",
      "intel_plane_alloc",
      "intel_atomic_state_alloc",
      "intel_crtc_alloc",
      "intel_crtc_state_alloc",
      "alloc_pt",
      "i915_gem_object_alloc",
      "i915_vma_alloc",
      "intel_engine_coredump_alloc",
      "intel_gt_coredump_alloc",
      "i915_gpu_coredump_alloc",
      "intel_sdvo_connector_alloc",
      "intel_sdvo_connector_alloc",
      "i915_lut_handle_alloc",
      "alloc_engines",
      "intel_context_alloc",
      "i915_block_alloc",
      "alloc_oa_regs",
      "alloc_oa_config_buffer",
      "i915_dependency_alloc",
      "alloc_cell",
      "alloc_pl",
      "alloc_context",
      "__rh_alloc",
      "alloc_dev",
      "mddev_alloc",
      "sock_kmalloc",
      "sock_omalloc",
      "sock_wmalloc",
      "qdisc_alloc",
      "alloc_param_target",
      "nci_skb_alloc",
      "alloc_pcie_link_state",
      "rfkill_alloc",
      "sg_alloc",
      "alloc_tty_struct",
      "tty_audit_buf_alloc",
      "tty_audit_buf_alloc",
      "tty_buffer_alloc",
      "vc_uniscr_alloc",
      "hcd_buffer_alloc",
      "alloc_async",
      "ehci_qh_alloc",
      "iso_sched_alloc",
      "iso_stream_alloc",
      "alloc_buffer",
      "xhci_ring_alloc",
      "xhci_segment_alloc",
      "xhci_segment_alloc",
      "ioctx_alloc",
      "alloc_buffer_head",
      "alloc_large_system_hash",
      "__d_alloc",
      "__d_alloc",
      "alloc_bprm",
      "posix_acl_alloc",
      "jbd2_alloc",
      "alloc_flex_gd",
      "alloc_flex_gd",
      "alloc_flex_gd",
      "dquot_alloc",
      "fat_cache_alloc",
      "alloc_pipe_info",
      "alloc_fdtable",
      "alloc_fs_context",
      "alloc_inode",
      "io_ring_ctx_alloc",
      "io_ring_ctx_alloc",
      "io_ring_ctx_alloc",
      "io_rsrc_node_alloc",
      "svc_rqst_alloc",
      "svc_rqst_alloc",
      "svc_rqst_alloc",
      "xprt_alloc",
      "xprt_alloc",
      "alloc_mnt_ns",
      "alloc_vfsmnt",
      "nfs_commitdata_alloc",
      "alloc_nfs_open_context",
      "alloc_nfs_open_dir_context",
      "nfs_direct_req_alloc",
      "nfs4_opendata_alloc",
      "nfs_page_alloc",
      "nfs_readhdr_alloc",
      "nfs_netns_client_alloc",
      "nfs_netns_object_alloc",
      "nfs_io_completion_alloc",
      "dst_alloc",
      "alloc_super",
      "alloc_ts_config",
      "reqsk_alloc",
      "inet_twsk_alloc",
      "xprt_switch_alloc",
      "__ring_buffer_alloc",
      "__ring_buffer_alloc",
      "alloc_msg",
      "alloc_msg",
      "audit_buffer_alloc",
      "alloc_tree",
      "alloc_chunk",
      "alloc_mark",
      "bpf_map_meta_alloc",
      "prog_array_map_alloc",
      "bpf_local_storage_map_alloc",
      "lwtunnel_state_alloc",
      "cpu_map_alloc",
      "dev_map_alloc",
      "htab_map_alloc",
      "map_iter_alloc",
      "map_iter_alloc",
      "trie_alloc",
      "ringbuf_map_alloc",
      "__bpf_map_area_alloc",
      "cpuset_css_alloc",
      "freezer_css_alloc",
      "alloc_cgroup_ns",
      "alloc_single_sgt",
      "rb_alloc",
      "alloc_perf_context",
      "alloc_task_ctx_data",
      "alloc_uprobe",
      "alloc_desc",
      "alloc_aggr_kprobe",
      "alloc_resource",
      "cpuacct_css_alloc",
      "sugov_policy_alloc",
      "sugov_tunables_alloc",
      "alloc_rootdomain",
      "__sigqueue_alloc",
      "taskstats_tgid_alloc",
      "alloc_posix_timer",
      "bpf_sk_storage_diag_alloc",
      "alloc_event_probe",
      "alloc_trace_kprobe",
      "alloc_trace_uprobe",
      "allocate_probes",
      "alloc_worker",
      "alloc_cpu_rmap",
      "alloc_uevent_skb",
      "radix_tree_node_alloc",
      "radix_tree_node_alloc",
      "nested_table_alloc",
      "nested_bucket_table_alloc",
      "sg_kmalloc",
      "xas_alloc",
      "pcpu_mem_zalloc",
      "pcpu_mem_zalloc",
      "anon_vma_alloc",
      "anon_vma_chain_alloc",
      "vlan_info_alloc",
      "vlan_vid_info_alloc",
      "p9_tag_alloc",
      "aarp_alloc",
      "alloc_mpc",
      "batadv_forw_packet_alloc",
      "rfcomm_dlc_alloc",
      "rfcomm_wmalloc",
      "caif_device_alloc",
      "ceph_osdmap_alloc",
      "ceph_pagelist_alloc",
      "alloc_generic_request",
      "linger_alloc",
      "lwork_alloc",
      "alloc_spg_mapping",
      "alloc_backoff",
      "alloc_crush_loc",
      "alloc_pg_mapping",
      "alloc_choose_arg_map",
      "decode_array_32_alloc",
      "alloc_crush_name",
      "xfrm_policy_alloc",
      "xfrm_state_alloc",
      "netdev_name_node_alloc",
      "devlink_fmsg_alloc",
      "metadata_dst_alloc",
      "fib6_info_alloc",
      "xt_counters_alloc",
      "nf_ct_tmpl_alloc",
      "nf_ct_tmpl_alloc",
      "nf_ct_expect_alloc",
      "flow_indr_dev_alloc",
      "neigh_hash_alloc",
      "neigh_hash_alloc",
      "neigh_alloc",
      "net_alloc",
      "net_alloc",
      "cgrp_css_alloc",
      "cgrp_css_alloc",
      "sk_prot_alloc",
      "sk_prot_alloc",
      "sock_hash_alloc",
      "sock_map_alloc",
      "__reuseport_alloc",
      "dccp_ackvec_alloc",
      "dsa_tree_alloc",
      "netlbl_secattr_alloc",
      "netlbl_catmap_alloc",
      "netlbl_secattr_cache_alloc",
      "fib_info_hash_alloc",
      "tnode_alloc",
      "tnode_alloc",
      "inet_frag_alloc",
      "ipmr_cache_alloc",
      "mr_table_alloc",
      "alloc_counters",
      "nexthop_alloc",
      "nexthop_grp_alloc",
      "nexthop_res_table_alloc",
      "udp_tunnel_nic_alloc",
      "udp_tunnel_nic_alloc",
      "ip6addrlbl_alloc",
      "aca_alloc",
      "node_alloc",
      "mca_alloc",
      "alloc_counters",
      "llc_sap_alloc",
      "ieee80211_key_alloc",
      "sta_info_alloc",
      "rate_control_alloc",
      "minstrel_ht_alloc",
      "mctp_route_alloc",
      "mctp_key_alloc",
      "__nf_conntrack_alloc",
      "genl_dumpit_info_alloc",
      "alloc_state",
      "digital_skb_alloc",
      "ovs_flow_alloc",
      "ovs_vport_alloc",
      "tbl_mask_array_alloc",
      "mask_alloc",
      "table_instance_alloc",
      "tbl_mask_cache_alloc",
      "alloc_one_pg_vec_page",
      "__phonet_device_alloc",
      "rds_message_alloc",
      "gss_pipe_alloc",
      "rsc_alloc",
      "rsi_alloc",
      "unix_gid_alloc",
      "ip_map_alloc",
      "rpc_sysfs_xprt_alloc",
      "rpc_sysfs_xprt_switch_alloc",
      "rpc_sysfs_client_alloc",
      "rpc_sysfs_object_alloc",
      "tipc_aead_mem_alloc",
      "tipc_tlv_alloc",
      "tipc_conn_alloc",
      "xfrm_hash_alloc",
      "xfrm_hash_alloc",
      "xfrm_pol_inexact_node_alloc",
      "alloc_elem",
      "alloc_symbol",
      "keyring_restriction_alloc",
      "avc_xperms_alloc",
      "avc_xperms_decision_alloc",
      "avc_xperms_decision_alloc",
      "avc_xperms_decision_alloc",
      "avc_xperms_decision_alloc",
      "snd_dma_vmalloc_alloc",
      "snd_dma_sg_alloc",
// some extended one from debugging
      "memdup_sockptr",
    ])
  }
}""",
    # * get dealloc functinos
    # * layer-level database
    # * 0 argument needed
    # * return [function name (string), function file (string), freearg (int)]
    # *   need to add HeapCommon part
    "GetDealloc": \
    """
from DeallocationFunction f
select f.getName(), f.getFile().getRelativePath(), f.getFreedArg()
    """,
    # * just as name suggests
    "GetHDef": \
    """import cpp
from Function f
where
  f.isDefined() and f.getFile() instanceof HeaderFile
select f.getName(), f.getFile().getRelativePath()""",
    "GetCDef": \
    """import cpp
from Function f
where
  f.isDefined() and f.getFile() instanceof CFile
select f.getName(), f.getFile().getRelativePath()""",
    "GetDef": \
    """import cpp
from Function f
where
  f.isDefined()
select f.getName(), f.getFile().getRelativePath()""",
    # * get the BB granularity callinfo with given function
    # * layer-level database
    # * 2 arguments needed
    #   * %s: func_name, name of the given function
    #   * %s: func_file, relative file of the given function
    #         could be the defined file or the declaration file
    # * return [calltype (string),
    #           callloc  (string),
    #           calleepacked (string),
    #           bb identifier,
    #           constant arg value (string),
    #           constant arg index (int),
    #           function arg packed (string),
    #           function arg index (int)]
    "GetCallInfo": \
    """import cpp
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.ControlFlowGraph
import semmle.code.cpp.pointsto.PointsTo
import semmle.code.cpp.pointsto.CallGraph

predicate arguementCall(VariableCall call) {
  exists(Parameter p, Function func |
    func = call.getEnclosingFunction() and
    p = func.getAParameter() and
    call.getExpr().(VariableAccess).getTarget() = p
  )
}

Parameter arguementCallParam(VariableCall call) {
  exists(Parameter p, Function func |
    func = call.getEnclosingFunction() and
    p = func.getAParameter() and
    call.getExpr().(VariableAccess).getTarget() = p
  |
    result = p
  )
}

Function getIndirectCallee(VariableCall call) {
  exists(Function callee | resolvedCall(call, callee) | result = callee)
}

string getWrapType(Call call) {
  if call instanceof FunctionCall
  then result = "direct"
  else
    if arguementCall(call)
    then result = "argcall"
    else result = "indirect"
}

predicate containConstantCall(Call call) {
  exists(Expr argument | argument = call.getAnArgument() and argument.isConstant())
}

predicate containFunctionCall(Call call) {
  exists(FunctionAccess access | access = call.getAnArgument())
}

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

from
  Function func,
  string func_name,
  File func_file,
  BasicBlock b,
  Call call,
  string calleepacked,
  string calltype,
  Function callee,
  string constargvalue,
  int constargidx,
  string functionargpacked,
  int functionargidx
where
  func_name = %s and
  func_file.getRelativePath() = %s and
  func = deriveFunctionWithHint(func_file, func_name) and
  b.getEnclosingFunction() = func and
  call = b.getANode() and
  calltype = getWrapType(call) and
  (
    if calltype = "direct"
    then
      callee = call.(FunctionCall).getTarget() and
      calleepacked = callee.getName() + "%%" + callee.getFile().getRelativePath()
    else
      if calltype = "argcall"
      then (callee = getIndirectCallee(call)
        and calleepacked = callee.getName() + "%%" + callee.getFile().getRelativePath() + "%%" + arguementCallParam(call).getIndex().toString()
      )
      else (
        callee = getIndirectCallee(call) and
        calleepacked = callee.getName() + "%%" + callee.getFile().getRelativePath()
      )
  ) and
  (
    if containConstantCall(call)
    then
      if exists(Expr argument, int n | argument = call.getArgument(n) and argument.isConstant() |
          constargvalue = argument.getValue() and
          constargidx = n
        )
      then 
        (1 = 1)
      else (
        constargvalue = "lucky" and
        constargidx = -1
      )
    else (
      constargvalue = "lucky" and
      constargidx = -1
    )
  ) and
  if containFunctionCall(call)
  then
    if exists(FunctionAccess access, int n, Function funcarg |
        access = call.getArgument(n) and funcarg = access.getTarget() |
        functionargpacked = funcarg.getName() + "%%" + funcarg.getFile().getRelativePath() and functionargidx = n
      )
    then
      (1 = 1)
    else (
      functionargpacked = "lucky" and functionargidx = -1
    )
  else (
    functionargpacked = "lucky" and functionargidx = -1
  )
select
  calltype,
  deriveLocation(call.getLocation()),
  calleepacked,
  bbIdentifier(b),
  constargvalue.replaceAll("\\n", ""),
  constargidx,
  functionargpacked,
  functionargidx""",
    # * batch version for above
    "GetCallInfoBatch": \
    """import cpp
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.ControlFlowGraph
import semmle.code.cpp.pointsto.PointsTo
import semmle.code.cpp.pointsto.CallGraph

predicate arguementCall(VariableCall call) {
  exists(Parameter p, Function func |
    func = call.getEnclosingFunction() and
    p = func.getAParameter() and
    call.getExpr().(VariableAccess).getTarget() = p
  )
}

Parameter arguementCallParam(VariableCall call) {
  exists(Parameter p, Function func |
    func = call.getEnclosingFunction() and
    p = func.getAParameter() and
    call.getExpr().(VariableAccess).getTarget() = p
  |
    result = p
  )
}

Function getIndirectCallee(VariableCall call) {
  // relies on pointsTo here
  exists(Function callee | resolvedCall(call, callee) | result = callee)
}

string getWrapType(Call call) {
  if call instanceof FunctionCall
  then result = "direct"
  else
    if arguementCall(call)
    then result = "argcall"
    else result = "indirect"
}

predicate containConstantCall(Call call) {
  exists(Expr argument | argument = call.getAnArgument() and argument.isConstant())
}

predicate containFunctionCall(Call call) {
  exists(FunctionAccess access | access = call.getAnArgument())
}

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

from
  int tag,
  Function func,
  string func_name,
  File func_file,
  BasicBlock b,
  Call call,
  string calleepacked,
  string calltype,
  Function callee,
  string constargvalue,
  int constargidx,
  string functionargpacked,
  int functionargidx
where
  (%s) and
  b.getEnclosingFunction() = func and
  call = b.getANode() and
  calltype = getWrapType(call) and
  (
    if calltype = "direct"
    then
      callee = call.(FunctionCall).getTarget() and
      calleepacked = callee.getName() + "%%" + callee.getFile().getRelativePath()
    else
      if calltype = "argcall"
      then (callee = getIndirectCallee(call)
        and calleepacked = callee.getName() + "%%" + callee.getFile().getRelativePath() + "%%" + arguementCallParam(call).getIndex().toString()
      )
      else (
        callee = getIndirectCallee(call) and
        calleepacked = callee.getName() + "%%" + callee.getFile().getRelativePath()
      )
  ) and
  (
    if containConstantCall(call)
    then
      if exists(Expr argument, int n | argument = call.getArgument(n) and argument.isConstant() |
          constargvalue = argument.getValue() and
          constargidx = n
        )
      then
        (1 = 1)
      else (
        constargvalue = "lucky" and
        constargidx = -1
      )
    else (
      constargvalue = "lucky" and
      constargidx = -1
    )
  ) and
  if containFunctionCall(call)
  then
    if exists(FunctionAccess access, int n, Function funcarg |
        access = call.getArgument(n) and funcarg = access.getTarget() |
        functionargpacked = funcarg.getName() + "%%" + funcarg.getFile().getRelativePath() and functionargidx = n
      )
    then
      (1 = 1)
    else (
      functionargpacked = "lucky" and functionargidx = -1
    )
  else (
    functionargpacked = "lucky" and functionargidx = -1
  )
select
  tag, 
  calltype,
  deriveLocation(call.getLocation()),
  calleepacked,
  bbIdentifier(b),
  constargvalue.replaceAll("\\n", ""),
  constargidx,
  functionargpacked,
  functionargidx
===
tag = %d and %s
===
func_name = %s and
func_file.getRelativePath() = %s and
func = deriveFunctionWithHint(func_file, func_name)""",
    # * <template> get the BB inside a given function
    # * layer-level database
    # * 2 arguments needed
    #   * %s: given function name
    #   * %s: given function hint file
    # * return [entrybb identifier (string),
    #           relation identifiers]
    "GetBasicBlock": \
    """import cpp
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.ControlFlowGraph

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" +  deriveLocation(bb.getEnd().getLocation())
}

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string relation(BasicBlock b) {
    exists(BasicBlock bb |
        bb = b.getASuccessor() or bb = b |
        result = bbIdentifier(b) + ";" + 
        bbIdentifier(bb)
    )
}

from Function func, string func_name, File func_file,  BasicBlock entry, BasicBlock b, int tag
where %s
select
  tag, 
  bbIdentifier(entry),
  relation(b)
===
tag = %d and %s and entry.getStart() = func.getEntryPoint() and b = entry.getASuccessor*()
===
func_name = %s and func_file.getRelativePath() = %s and func = deriveFunctionWithHint(func_file, func_name)""",
    # * get the unreg functions from notifier
    # * layer-level database
    # * 2 arguments needed
    #   * %s: function name
    #   * %s: function file
    # * return [unreg call loc (string),
    #           unregfunc name (string),
    #           unregfunc file (string),
    #           bb identifier,
    #           constant variable value
    #           constant variable index]
    "GetUnregFromNotifier":\
    """
    import cpp

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

from
  Function func,
  string func_name,
  File func_file,
  FunctionAccess fa,
  SwitchCase sc,
  SwitchStmt ss,
  Stmt st,
  FunctionCall fc,
  BasicBlock b,
  string constargvalue,
  int constargidx
where
  func_name = %s and
  func_file.getRelativePath() = %s and
  func = deriveFunctionWithHint(func_file, func_name) and
  sc.getEnclosingFunction() = f and
  sc = ss.getASwitchCase() and
  st = sc.getAStmt() and
  sc.getExpr().toString().matches(["NETDEV_DOWN", "NETDEV_UNREGISTER", "NETDEV_GOING_DOWN"]) and
  fc.getEnclosingElement+() = st and
  fc = b.getANode() and
  (
    exists( Expr argument, int n | 
    argument = fc.getArgument(n) and argument.isConstant() |
    constargvalue = argument.getValue() and
    constargidx = n )
    or (
      constargvalue = "lucky" and
      constargidx = -1
    )
  )
select
  deriveLocation(fc.getLocation()),
  fc.getTarget().getName(),
  fc.getTarget().getFile().getRelativePath(),
  bbIdentifier(b),
  constargvalue.replaceAll("\\n", ""),
  constargidx""",
    # don't forget to patch the codeql pto code
    # * find deref sites with given dealloc site
    # * layer-level database
    # * 3 arguments needed
    #   * %s: dealloc call location
    #   * %d: dealloc arg index
    #   * %s: layer identifier
    # * return [confidence (float), deallocation call, deallocation call location]
    "PointsToAnlysisS1": \
    """
predicate isStructOrTypedef(Type t) { t instanceof Struct or t instanceof TypedefType }

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

predicate deallocsite(Expr e) {
  exists(Call c |
    deriveLocation(c.getLocation()) = %s and
    e = c.getArgument(%d)
  )
}

class DeallocSite extends PointsToExpr {
  DeallocSite() { deallocsite(this) }

  override predicate interesting() { deallocsite(this) }
}

predicate insideLayer(Function func) {
  func.getFile().getRelativePath().matches("%%%s%%")
}

from DeallocSite site, Call fc
where
  fc = site.pointsTo() and insideLayer(fc.getEnclosingFunction())
select site.confidence(), fc, deriveLocation(fc.getLocation())""",
    # alias
    # 2 arguments needed
    "PointsToAnlysisS2": \
    """

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

predicate insideLayer(Function func) {
  func.getFile().getRelativePath().matches("%%%s%%")
}

predicate argumentToUtil(Expr e) {
  exists(FunctionCall fc |
    e = fc.getAnArgument() and
    not (fc.getTarget().isDefined() and insideLayer(fc.getTarget())) and
    // don't care re-allocation
    not fc.getTarget() instanceof AllocationFunction and
    // don't care double free
    not fc.getTarget() instanceof DeallocationFunction
  )
}

class DerefSite extends PointsToExpr {
  DerefSite() {
    dereferenced(this) or
    argumentToUtil(this)
  }

  override predicate interesting() {
    dereferenced(this) or
    argumentToUtil(this)
  }
}

from DerefSite site, Call fc, BasicBlock bb, Function f, string pointsToValue, BasicBlock pbb
where
  deriveLocation(fc.getLocation()).matches([%s]) and
  fc = site.pointsTo() and
  site = bb.getANode() and
  f = site.getEnclosingFunction() and
  insideLayer(f) and
  fc = pbb.getANode() and
  pointsToValue = "call---" + deriveLocation(fc.getLocation()) + "---" + bbIdentifier(pbb) + "---" + fc.getTarget().toString() + "---" + fc.getTarget().getFile().getRelativePath() + "---" + fc.getEnclosingFunction().toString() + "---" + fc.getEnclosingFunction().getFile().getRelativePath()
select
  site.confidence(),
  deriveLocation(site.getLocation()),
  bbIdentifier(bb),
  f.getName(), 
  f.getFile().getRelativePath(), 
  pointsToValue""",
    # alike
    "PointsToAnalysis": \
    """

predicate isStructOrTypedef(Type t) { t instanceof Struct or t instanceof TypedefType }

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

predicate deallocsite(Expr e) {
  exists(Call c |
    deriveLocation(c.getLocation()) = %s and
    e = c.getArgument(%d) and
    isStructOrTypedef(e.getType().(PointerType).getBaseType())
  )
}

class DeallocSite extends PointsToExpr {
  DeallocSite() { deallocsite(this) }

  override predicate interesting() { deallocsite(this) }
}

predicate argumentToExport(Expr e) {
  exists(FunctionCall fc |
    e = fc.getAnArgument() and
    not fc.getTarget().isDefined() and
    // don't care re-allocation
    not fc.getTarget() instanceof AllocationFunction and
    // don't care double free
    not fc.getTarget() instanceof DeallocationFunction
  )
}

predicate insideLayer(Function func) {
  func.getFile().getRelativePath().matches("%%%s%%")
}

predicate argumentToUtil(Expr e) {
  exists(FunctionCall fc |
    e = fc.getAnArgument() and
    not (fc.getTarget().isDefined() and insideLayer(fc.getTarget())) and
    // don't care re-allocation
    not fc.getTarget() instanceof AllocationFunction and
    // don't care double free
    not fc.getTarget() instanceof DeallocationFunction
  )
}

class DerefSite extends PointsToExpr {
  DerefSite() {
    dereferenced(this) or
    argumentToUtil(this)
  }

  override predicate interesting() {
    dereferenced(this) or
    argumentToUtil(this)
  }
}

from DeallocSite o1, DerefSite o2, Expr e1, Expr e2, BasicBlock bb, Function f, string pointsToValue, BasicBlock pbb
where 
  e1 = o1.pointsTo() and e2 = o2.pointsTo() and
  o1.getType() = o2.getType() and
  e1 = e2 and
  o2 = bb.getANode() and
  f = o2.getEnclosingFunction() and
  insideLayer(f) and
  e1 instanceof FunctionCall and
  e1 = pbb.getANode() and
  pointsToValue = "call---" + deriveLocation(e1.(FunctionCall).getLocation()) + "---" + bbIdentifier(pbb) + "---" + e1.(FunctionCall).getTarget().toString() + "---" + e1.(FunctionCall).getTarget().getFile().toString() + "---" + e1.getEnclosingFunction().toString() + "---" + e1.getEnclosingFunction().getFile().toString()
select
  o2.confidence(),
  deriveLocation(o2.getLocation()),
  bbIdentifier(bb),
  f.getName(),
  f.getFile().getRelativePath(),
  pointsToValue""",
    # * get the BB edge whose relation sanitize by condition
    # * layer-level database
    # * 2 arguments needed
    #   * %s: function name
    #   * %s: function hint file
    # * return ...
    "GetSanitizeConditions": \
    """import cpp
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.ControlFlowGraph

Function deriveFunctionWithHint(File file, string funcname)
{
  if file instanceof CFile
  then
    exists(Function func | func.getFile() = file and func.hasName(funcname) | result = func)
  else
    exists(Function func, Declaration delc | 
      delc = func.getADeclaration() and delc.getFile() = file and func.hasName(funcname) |
      result = func)
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

from
  int tag,
  Function func,
  string func_name,
  File func_file,
  BasicBlock pre,
  BasicBlock sub,
  string relation,
  string param,
  int paramidx
where %s
select
    tag,
    bbIdentifier(pre),
    bbIdentifier(sub),
    relation,
    param,
    paramidx
===
tag = %d and %s
===
    func_name = %s and
    func_file.getRelativePath() = %s and
    func = deriveFunctionWithHint(func_file, func_name) and
    pre.getEnclosingFunction() = func and
    sub.getEnclosingFunction() = func and
    (
      (sub = pre.getATrueSuccessor() and
      relation = "True")
      or
      (sub = pre.getAFalseSuccessor() and
      relation = "False")
    ) and
    (
      exists(VariableAccess va, Parameter p | va = pre.getEnd() and p = va.getTarget() |
        param = p.toString() and
        p = func.getParameter(paramidx)
      )
      or
      exists(VariableAccess va, NotExpr ne, Parameter p |
        ne = pre.getEnd() and va = ne.getOperand() and p = va.getTarget()
      |
        // dumb solution ...
        param = "!" + p.toString() and
        p = func.getParameter(paramidx)
      )
    )""",
    # get null write location and bb
    "GetSNullWrite": \
    """import cpp

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

from BasicBlock bb, AssignExpr e, string s1, string s2, int tag
where %s
select tag, s2, s1, deriveLocation(e.getLocation())
===
tag = %d and %s
===
bbIdentifier(bb).matches(
    %s
) and
e = bb.getANode() and 
e.getRValue().isConstant() and
e.getRValue().toString().matches("0") and
s1 = e.getLValue().toString() and
s2 = e.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().(PointerType).getBaseType().toString()""",
    #
    "GetBBConditions": \
    """import cpp
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.ControlFlowGraph

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string bbIdentifier(BasicBlock bb) {
	if not exists(string s, Location loc |
          loc = bb.getStart().getLocation() and
          s = deriveLocation(loc)
        )
	then
		// now only see BlockStmt case
		result = deriveLocation(bb.getStart().(BlockStmt).getStmt(0).getLocation()) +
		"+" +
		deriveLocation(bb.getEnd().getLocation())
	else
		result = deriveLocation(bb.getStart().getLocation()) + "+" + 
		deriveLocation(bb.getEnd().getLocation())
}

string deriveFunctionCallCondition(FunctionCall fc) {
    if (
        fc.getTarget().hasName(["test_bit", "test_and_set_bit", "test_and_clear_bit"])
    )
    then
        result = "[FunctionCall]---" +
        fc.getArgument(0).toString() + "---" +
        fc.getArgument(0).getValue().toString() + "---" +
        fc.getArgument(1).toString()     
    else
        result = "unknown"
}

string derivePFACondition(PointerFieldAccess pfa) {
    result = "[PointerFieldAccess]---" +
        pfa.toString() + "---" +
        pfa.getQualifier().(VariableAccess).getTarget().getType()
        .(PointerType).getBaseType().toString()
}

string deriveContent(Expr e) {
    /* FunctionCall: bits read */
    if e instanceof FunctionCall
    then
        result = deriveFunctionCallCondition(e)
    else
    /* PointerFieldAccess */
    if e instanceof PointerFieldAccess
    then
        result = derivePFACondition(e)
    else
    /* NotExpr */
    if e instanceof NotExpr
    then
        result = "[NOT]---" + deriveContent(e.(NotExpr).getOperand())
    else
    /* EQExpr */
    if e instanceof EQExpr
    then (
        // only care constant right operant situation
        if (
            e.(EQExpr).getRightOperand().isConstant() and
            e.(EQExpr).getLeftOperand() instanceof PointerFieldAccess
        )
        then
            if e.(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType()
                instanceof PointerType
            then
                result = "[EQExpr]---" +
                e.(EQExpr).getRightOperand().getValue() + "---" +
                e.(EQExpr).getLeftOperand().toString() + "---" +
                e.(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType()
                .(PointerType).getBaseType().toString()
            else
                result = "[EQExpr]---" +
                e.(EQExpr).getRightOperand().getValue() + "---" +
                e.(EQExpr).getLeftOperand().toString() + "---" +
                e.(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().toString() + "_field_"
        else
            result = "unknown"
    )
    else
    if e instanceof NEExpr
    then (
        // only care constant right operant situation
        if ( 
            e.(NEExpr).getRightOperand().isConstant() and
            e.(NEExpr).getLeftOperand() instanceof PointerFieldAccess
        )
        then
            if e.(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType()
                instanceof PointerType
            then
                result = "[NEExpr]---[PointerFieldAccess]---" +
                e.(NEExpr).getRightOperand().getValue() + "---" +
                e.(NEExpr).getLeftOperand().toString() + "---" +
                e.(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType()
                .(PointerType).getBaseType().toString()
            else
                result = "[NEExpr]---[PointerFieldAccess]---" +
                e.(NEExpr).getRightOperand().getValue() + "---" +
                e.(NEExpr).getLeftOperand().toString() + "---" +
                // recursive field here
                e.(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().toString() + "_field_"
        else
            result = "unknown"
    )
    else
        result = "unknown"
}

string deriveRelation(BasicBlock a, BasicBlock b) {
    if b = a.getATrueSuccessor()
    then
        result = "true"
    else
        if b = a.getAFalseSuccessor()
        then
            result = "false"
        else
            result = "unknown"
}

from Function f, BasicBlock prev, BasicBlock succ, string relation, string condition, int tag
where %s
select tag, relation, condition
===
tag = %d and f.hasName(%s) and
f = prev.getEnclosingFunction() and
f = succ.getEnclosingFunction() and
%s
===
bbIdentifier(prev).matches(%s) and
bbIdentifier(succ).matches(%s) and
relation = deriveRelation(prev, succ)
and
if (
    relation.matches(["true", "false"])
)
then (
    condition = deriveContent(prev.getEnd())
)
else (
    condition = "unknown"
)""",
    # locks related
    "GetGlobalLockSimple": \
    """import cpp

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string lockunlockfuncCall(FunctionCall fc) {
    exists(Function lock, Function unlock, string s1, string s2 |
        s1 = lock.getName().toString() and
        s1.matches(["%_lock", "%_lock_nested", "%_lock_bh", "%_lock_irqsave", "%_lock_irq"]) and
        s2 = unlock.getName().toString() and
        s2.matches(["%_unlock", "%_unlock_nested", "%_unlock_bh", "%_unlock_irqrestore", "%_unlock_irq"]) and 
        s1.splitAt("_lock") = s2.splitAt("_unlock") and
        (
            ( lock = fc.getTarget() and result = "locking") or 
            ( unlock = fc.getTarget() and result = "unlocking" )
        )
    )
}

from GlobalVariable v, VariableAccess vc, FunctionCall fc, AddressOfExpr ae
where
    v.getType().findRootCause().toString().matches([
        "rwlock_t", "spinlock_t", "mutex"
    ]) and
    vc.getTarget() = v and
    ae.getOperand() = vc and
    ae = fc.getAnArgument()
select 
    deriveLocation(fc.getLocation()),
    fc.getTarget().getName(),
    fc.getTarget().getFile().getRelativePath(),
    deriveLocation(v.getLocation()),
    lockunlockfuncCall(fc),
    fc.getEnclosingFunction().getName(),
    fc.getEnclosingFunction().getFile().getRelativePath()""",
    #
    "GetGStructLock": \
    """import cpp

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

string lockunlockfuncCall(FunctionCall fc) {
    exists(Function lock, Function unlock, string s1, string s2 |
        s1 = lock.getName().toString() and
        s1.matches(["%_lock", "%_lock_nested", "%_lock_bh", "%_lock_irqsave", "%_lock_irq"]) and
        s2 = unlock.getName().toString() and
        s2.matches(["%_unlock", "%_unlock_nested", "%_unlock_bh", "%_unlock_irqrestore", "%_unlock_irq"]) and 
        s1.splitAt("_lock") = s2.splitAt("_unlock") and
        (
            ( lock = fc.getTarget() and result = "locking") or 
            ( unlock = fc.getTarget() and result = "unlocking" )
        )
    )
}

from GlobalVariable v, ValueFieldAccess fa, FunctionCall fc, AddressOfExpr ae
where
    fa.getQualifier().(VariableAccess).getTarget() = v and
    fa.getTarget().getType().findRootCause().toString().matches([
        "rwlock_t", "spinlock_t", "mutex"
    ]) and
    fa = ae.getOperand() and
    ae = fc.getAnArgument()
select
    deriveLocation(fc.getLocation()),
    fc.getTarget().getName(),
    fc.getTarget().getFile().getRelativePath(),
    deriveLocation(v.getLocation()),
    lockunlockfuncCall(fc),
    fc.getEnclosingFunction().getName(),
    fc.getEnclosingFunction().getFile().getRelativePath()""",
    # dynamic locks
    "GetDLockLocations": \
    """import cpp
import semmle.code.cpp.pointsto.PointsTo
import semmle.code.cpp.controlflow.StackVariableReachability

// --- define lock/unlock initialization
predicate lockinit(Expr e, FunctionCall fc) {
  (
    // read write lock
    (
      fc.getTarget().hasName("__rwlock_init") and
      fc.isInMacroExpansion()
    ) or
    // mutex lock
    (
      fc.getTarget().hasName("__mutex_init") and
      fc.isInMacroExpansion()
    ) or
    // spinlock
    (
      fc.getTarget().hasName("spinlock_check") and
      fc.isInMacroExpansion() and
      exists(MacroInvocation inv | 
        inv.getMacroName() = "spin_lock_init" and
        inv.getLocation().toString() = fc.getLocation().toString())
    )
  ) and 
  fc.getAnArgument() = e
}

class LockInitExpr extends PointsToExpr {
  FunctionCall initfunc;

  LockInitExpr() { lockinit(this, initfunc) }

  override predicate interesting() { any() }

  FunctionCall getInitCall() { result = initfunc }
}

// --- define lock/unlock function call
abstract class LockUnLockCall extends FunctionCall {
  LockUnLockCall() { any() }

  abstract string getLockUnlockType();

  abstract string getAction();

  abstract FunctionCall getPCall();

}

class RWLockUnLockCall extends LockUnLockCall {
  string lockorunlock;
  
  RWLockUnLockCall() {
    (
      this.getTarget().hasName([
        "__raw_read_lock", "__raw_read_lock_irqsave", "__raw_read_lock_irq",
        "__raw_read_lock_bh", "__raw_write_lock_irqsave", "__raw_write_lock_irq",
        "__raw_write_lock_bh", "__raw_write_lock"
      ]) and 
      lockorunlock = "locking"
    ) or (
      this.getTarget().hasName([
        "__raw_write_unlock", "__raw_read_unlock", "__raw_read_unlock_irqrestore",
        "__raw_read_unlock_irq", "__raw_read_unlock_bh", "__raw_write_unlock_irqrestore",
        "__raw_write_unlock_irq", "__raw_write_unlock_bh"
      ]) and 
      lockorunlock = "unlocking"
    )
  }

  override string getLockUnlockType() { result = "rwlock" }

  override string getAction() { result = lockorunlock }

  // though read_lock, read_trylock and read_lock_irq ...
  // are implemented by macro, but after expanded, it will not disturb
  // pointsTo analysis so just return itself
  override FunctionCall getPCall() { result = this }
}

class SpinLockUnLockCall extends LockUnLockCall {
  string lockorunlock;
  
  SpinLockUnLockCall() {
    (
      this.getTarget().hasName([
        "spin_lock", "spin_lock_bh", "spin_trylock",
        "spin_lock_irq", "spin_trylock_bh", "spin_trylock_irq",
        "_raw_spin_trylock", "_raw_spin_trylock_bh", "_raw_spin_lock",
        "_raw_spin_lock_irqsave", "_raw_spin_lock_irq", "_raw_spin_lock_bh",
        "_raw_read_trylock", "_raw_read_lock", "_raw_read_lock_irqsave",
        "_raw_read_lock_irq", "_raw_read_lock_bh", "_raw_write_trylock",
        "_raw_write_lock", "_raw_write_lock_irqsave", "_raw_write_lock_irq",
        "_raw_write_lock_bh", "_raw_spin_lock_nested",
        "_raw_spin_lock_irqsave_nested", "_raw_spin_lock_nest_lock"
      ]) and 
      lockorunlock = "locking"
    ) or (
      this.getTarget().hasName([
        "spin_unlock", "spin_unlock_bh", "spin_unlock_irq",
        "spin_unlock_irqrestore", "_raw_spin_unlock",
        "_raw_spin_unlock_irqrestore", "_raw_spin_unlock_irq",
        "_raw_spin_unlock_bh", "_raw_read_unlock", "_raw_read_unlock_irqrestore",
        "_raw_read_unlock_irq", "_raw_read_unlock_bh", "_raw_write_unlock",
        "_raw_write_unlock_irqrestore", "_raw_write_unlock_bh", "_raw_write_unlock_irq"
      ]) and 
      lockorunlock = "unlocking"
    )
  }

  override string getLockUnlockType() { result = "spinlock" }

  override string getAction() { result = lockorunlock }

  // spinlock like uses spinlock_check function
  // which will derive rawlock from spinlock and disturb pointsTo
  override FunctionCall getPCall() { 
    if this.isInMacroExpansion()
    then
      if exists(FunctionCall checkcall | 
          checkcall.getBasicBlock() = this.getBasicBlock() and
          checkcall.getTarget().hasName("spinlock_check") |
          result = checkcall)
      then (1 = 1)
      else
        result = this
    else
      result = this
  }
}

class MutexLockUnLockCall extends LockUnLockCall {
  string lockorunlock;
  
  MutexLockUnLockCall() {
    (
      this.getTarget().hasName([
        "mutex_trylock_recursive", "mutex_lock_nested", "_mutex_lock_nest_lock",
        "mutex_lock_killable_nested", "mutex_lock_interruptible_nested", "mutex_lock_io_nested",
        "ww_mutex_lock", "mutex_lock_interruptible", "mutex_lock_killable",
        "mutex_lock_io", "mutex_trylock", "ww_mutex_lock", "ww_mutex_lock_interruptible"
      ]) and 
      lockorunlock = "locking"
    ) or (
      this.getTarget().hasName([
        "mutex_unlock"
      ]) and 
      lockorunlock = "unlocking"
    )
  }

  override string getLockUnlockType() { result = "mutex" }

  override string getAction() { result = lockorunlock }

  // mutex is like read write lock
  override FunctionCall getPCall() { result = this }
}

class MayLockULock extends PointsToExpr {
  LockUnLockCall call;

  MayLockULock() { call.getPCall().getAnArgument() = this }

  override predicate interesting() { any() }

  LockUnLockCall getLCall() { result = call }
}

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

from MayLockULock lockunlock, LockUnLockCall lockunlockcall, LockInitExpr init, FunctionCall initcall, Function encloser
where
  init.pointsTo() = lockunlock.pointsTo() and
  initcall = init.getInitCall() and
  lockunlockcall = lockunlock.getLCall() and
  encloser = lockunlock.getEnclosingFunction()
select 
  deriveLocation(lockunlockcall.getLocation()),
  lockunlockcall.getTarget().getName(),
  lockunlockcall.getTarget().getFile().getRelativePath(), 
  deriveLocation(initcall.getLocation()),
  lockunlockcall.getAction(),
  encloser.getName(),
  encloser.getFile().getRelativePath()""",
    # unified lock
    "GetALock": \
    """import cpp

string deriveLocation(Location loc) {
    result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

from FunctionCall fc, Function func, string lockunlock, string identifier
where
    identifier = "unified" and
    (
        func = fc.getTarget() and
        (
            (
                func.hasName(["lock_sock", "lock_sock_fast", "lock_sock_nested", "__lock_sock", "rtnl_lock"]) and
                lockunlock = "locking"    
            ) or (
                func.hasName(["release_sock", "unlock_sock_fast", "__releases_sock", "rtnl_unlock"]) and
                lockunlock = "unlocking" 
            )
        )
    )
select
    deriveLocation(fc.getLocation()),
    func.getName(),
    func.getFile().getRelativePath(),
    identifier,
    lockunlock,
    fc.getEnclosingFunction(),
    fc.getEnclosingFunction().getFile().getRelativePath()""",
    # bit related
    "GetBitsOps": \
    """import cpp

string deriveLocation(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" + loc.getStartColumn().toString()
}

from FunctionCall fc, Function f
where
  f = fc.getTarget() and
  f.hasName(%s)
select
    deriveLocation(fc.getLocation()),
    fc.getArgument(0),
    fc.getArgument(0).getValue(),
    fc.getArgument(1),
    fc.getEnclosingFunction().getName(),
    fc.getFile().getRelativePath(),
    fc.getTarget().getName()"""
}