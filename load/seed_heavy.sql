-- 부하 전용 heavy 시드: 마이페이지/주문목록의 "전체 조회 후 컷" 병목(L-2)을 노출한다.
-- user001~user020에 주문을 대량 생성한다. 데모 기본 시드와 별개로 필요할 때만 적재한다.
USE zeti_db;
SET SESSION cte_max_recursion_depth = 20000;

-- 0..9999 시퀀스
DROP TEMPORARY TABLE IF EXISTS tmp_n;
CREATE TEMPORARY TABLE tmp_n (n INT PRIMARY KEY);
INSERT INTO tmp_n (n)
WITH RECURSIVE r(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM r WHERE n < 9999)
SELECT n FROM r;

-- 대상: user_id 140000000..140000019 (앞 20명)
INSERT INTO orders (user_id, address_id, total_amount, status, ordered_at)
SELECT u.user_id,
       (SELECT a.address_id FROM addresses a WHERE a.user_id = u.user_id LIMIT 1),
       ROUND(1000 + (t.n % 500) * 13.7, 2),
       ELT(1 + (t.n % 4), 'PENDING','PAID','SHIPPED','DELIVERED'),
       NOW() - INTERVAL t.n MINUTE
FROM users u
JOIN tmp_n t
WHERE u.user_id BETWEEN 140000000 AND 140000019;
