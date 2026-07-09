class CommandSession {
  constructor() {
    this.selectedDevice = null;
    this.selectedAdbAddress = null;
    this.lastResult = null;
    this.history = [];
    this.undone = [];
  }

  rememberPrepare(selector, payload) {
    const resolvedDevice = payload.resolvedDevice || {};
    this.selectedDevice = {
      deviceId: resolvedDevice.id || selector.deviceId,
      udId: resolvedDevice.udId || selector.udId,
    };
    this.selectedAdbAddress = payload.adbAddress || this.selectedAdbAddress;
    this.lastResult = payload;
    this.history.push({
      name: "prepare_android_debug",
      selector: { ...selector },
      adbAddress: payload.adbAddress,
      resolvedDevice,
      reversible: true,
    });
    this.undone = [];
  }

  rememberOpenApp(adbAddress, appId, payload) {
    this.selectedAdbAddress = adbAddress || this.selectedAdbAddress;
    this.lastResult = payload;
    this.history.push({
      name: "open_app",
      adbAddress,
      appId,
      reversible: true,
    });
    this.undone = [];
  }

  rememberIrreversible(name, payload, metadata = {}) {
    this.lastResult = payload;
    this.history.push({
      name,
      reversible: false,
      ...metadata,
    });
    this.undone = [];
  }

  snapshot() {
    return {
      selected_device: this.selectedDevice,
      selected_adb_address: this.selectedAdbAddress,
      last_result: this.lastResult,
      history_size: this.history.length,
      undone_size: this.undone.length,
    };
  }

  async undo(app) {
    if (!this.history.length) {
      return { ok: false, message: "没有可撤销的动作。" };
    }
    const action = this.history.pop();
    if (!action.reversible) {
      this.undone.push(action);
      return {
        ok: false,
        message: `动作 ${action.name} 不支持撤销。`,
        action,
      };
    }

    let result;
    if (action.name === "prepare_android_debug") {
      const udid = action.resolvedDevice.udId || action.selector.udId;
      result = await app.backend.releaseDevice({ udid });
    } else if (action.name === "open_app") {
      result = app.adb.killApp(action.adbAddress, action.appId);
    } else {
      this.undone.push(action);
      return {
        ok: false,
        message: `动作 ${action.name} 暂不支持撤销。`,
        action,
      };
    }

    this.undone.push(action);
    this.lastResult = result;
    return { ok: true, action, result };
  }

  async redo(app) {
    if (!this.undone.length) {
      return { ok: false, message: "没有可重做的动作。" };
    }
    const action = this.undone.pop();
    if (action.name === "prepare_android_debug") {
      const selector = action.selector || {};
      const result = await app.backend.prepareAndroidDebug({
        deviceId: selector.deviceId,
        udid: selector.udId,
      });
      this.history.push(action);
      this.selectedAdbAddress = result.adbAddress || this.selectedAdbAddress;
      this.lastResult = result;
      return { ok: true, action, result };
    }
    if (action.name === "open_app") {
      const result = app.adb.openApp(action.adbAddress, action.appId);
      this.history.push(action);
      this.lastResult = result;
      return { ok: true, action, result };
    }
    return { ok: false, message: `动作 ${action.name} 暂不支持重做。`, action };
  }
}

module.exports = {
  CommandSession,
};
