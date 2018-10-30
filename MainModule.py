import CaptureModule
import FeatureExtractModule
import MyTestModule
from multiprocessing import Process

if __name__ == "__main__":
    processes = []
    try:
        processCapture = Process(target = CaptureModule.capture())
        processFeature = Process(target = FeatureExtractModule.featureExtract())
        # processTest = Process(target=MyTestModule.featureExtract())
        processCapture.start()
        processFeature.start()
        # processTest.start()

    except KeyboardInterrupt:
        processCapture.terminate()
        processFeature.terminate()
        # processTest.terminate()

    processCapture.join()
    processFeature.join()
    # processTest.join()
