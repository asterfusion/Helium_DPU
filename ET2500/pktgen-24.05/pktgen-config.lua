local total_ports = 14

-- 循环遍历所有端口并设置数据包大小
for port = 8, 12 do
    if port ~= 7 and port ~= 11 then
        pktgen.set(port, "size", 1518)    -- 设置每个端口的数据包大小为512字节
    end
end
-- pktgen.set(7,"size",218)

-- os.execute("sleep 1")
-- pktgen.set(7,"size",512)
-- os.execute("sleep 1")
-- pktgen.set(7,"size",1518)
pktgen.start("all")