package com.venustech.tacacs.client;

import com.venustech.tacacs.protocol.entity.base.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.AbstractQueuedSynchronizer;

/**
 * @author zhangxin
 * 2018/8/29
 */
public class TacacsFuture implements Future {

    private Logger logger = LoggerFactory.getLogger(TacacsFuture.class);


    private Sync sync;
    private Packet request;
    private Packet response;

    private long startTime;
    private long responseTimeThreshold = 5000;

    public TacacsFuture(Packet request){
        sync = new Sync();
        this.request = request;
        startTime = System.currentTimeMillis();
    }


    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isCancelled() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isDone() {
        return sync.isDone();
    }

    @Override
    public Object get() throws InterruptedException, ExecutionException {
        sync.acquire(-1);
        if(this.response != null){
            return response;
        }
        return null;
    }

    @Override
    public Object get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        boolean success = sync.tryAcquireNanos(-1, unit.toNanos(timeout));
        if (success) {
            if (this.response != null) {
                return response;
            } else {
                return null;
            }
        } else {
            throw new RuntimeException("Timeout exception." );
        }
    }

    public void done(Packet response){
        this.response = response;
        sync.release(1);
        long responseTime = System.currentTimeMillis() - startTime;
        //System.out.println("server response time is " + responseTime + " ms");
    }

    /** 使用AQS同步器来实现对服务器的准确应答 **/
    static class Sync extends AbstractQueuedSynchronizer{

        private static final long serialVersionUID = 1L;

        private int done = 1;
        private int pending = 0;

        @Override
        protected boolean tryAcquire(int arg) {
            return getState() == done;
        }

        @Override
        protected boolean tryRelease(int arg) {
            if(getState() == pending){
                if(compareAndSetState(pending, done)){
                    return true;
                }
            }else{
                return true;
            }
            return false;
        }

        public boolean isDone(){
            return getState() == done;
        }
    }
}
