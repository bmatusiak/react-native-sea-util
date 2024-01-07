import { NativeModules, Platform } from 'react-native';

// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-explicit-any
const shim: any = require('./sea.shim');

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
