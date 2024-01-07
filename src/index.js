import { NativeModules, Platform } from 'react-native';

const shim = require('./sea.shim');

const LINKING_ERROR =
  `The package 'react-native-sea-util' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const SeaUtil = NativeModules.SeaUtil
  ? NativeModules.SeaUtil
  : new Proxy(
    {},
    {
      get() {
        throw new Error(LINKING_ERROR);
      },
    }
  );

shim(SeaUtil);

export default SeaUtil;
