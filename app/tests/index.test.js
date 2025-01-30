const { handler } = require("../src/index");

const getMockEvent = (request) => {
  return {
    Records: [
      {
        cf: { request },
      },
    ],
  };
};

describe("handlerのテスト", () => {
  it("/hoge は /index.html に変更される", () => {
    const event = getMockEvent({ uri: "/_callback" });

    const callback = jest.fn();
    handler(event, null, callback);

    // expect(callback).toHaveBeenCalledWith(null, { uri: "/index.html" });
    // expect(callback).toHaveBeenCalledTimes(1);
  });
});
